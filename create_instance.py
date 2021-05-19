import boto3
import logging
import os
import re
import sys
import yaml

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from typing import List

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def get_ami_ids(names: List[str], region: str) -> List[str]:
    log.info(f"Finding AMI ids that match {names} in {region}")
    ssm = boto3.client('ssm', region_name=region)
    response = ssm.get_parameters(Names=names)

    metadata: dict = response['ResponseMetadata']
    if metadata['HTTPStatusCode'] == 200:
        params: List[dict] = response['Parameters']
        ami_ids: List[str] = [param.get('Value') for param in params]

    log.debug(f"Found AMI ids {ami_ids}")
    return ami_ids


def generate_volumes(config: dict, user_script: str) -> tuple:
    log.info("Generating volume config")
    volumes: List[dict] = []
    for volume_config in config['server']['volumes']:
        volume: dict = {
            'DeviceName': volume_config['device'],
            'Ebs': {
                'VolumeSize': volume_config['size_gb'],
                'DeleteOnTermination': True
            }
        }
        volumes.append(volume)
        if volume_config['mount'] != '/':
            user_script += (
                f"while [ ! -e {volume_config['device']} ]; do sleep 1; done\n"
                f"sudo mkfs.xfs {volume_config['device']}\n"
                f"sudo mkdir {volume_config['mount']}\n"
                f"sudo mount {volume_config['device']} {volume_config['mount']}\n"
                f"sudo chgrp users {volume_config['mount']}\n"
                f"sudo chmod 775 {volume_config['mount']}\n"
            )
    log.debug(f"Generated volume config {volumes}")
    return volumes, user_script


def generate_ssh_keys(config: dict, user_script: str) -> tuple:
    log.info("Generating ssh keys")
    ssh_keys: dict = {}
    for user in config['server']['users']:
        key: object = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )

        private_key: bytes = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption()
        )

        public_key: bytes = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )

        # Regex match on the ssh_key in the provision file so we can grab the ley label
        config_ssh_key_placeholder = re.match(r'^--(.*)-- (.*)$', user['ssh_key'])
        ssh_key_label = config_ssh_key_placeholder[2]

        ssh_keys[user['login']] = {
            'private_key': private_key.decode(),
            'public_key': f'{public_key.decode()} {ssh_key_label}'
        }

        user_script += (
            f"sudo adduser -g {config['user_group']} {user['login']}\n"
            f"sudo -u {user['login']} mkdir ~{user['login']}/.ssh\n"
            f"sudo -u {user['login']} chmod 700 ~{user['login']}/.ssh\n"
            f"sudo -u {user['login']} sh -c \"echo '{public_key.decode()} {ssh_key_label}' > ~{user['login']}/.ssh/authorized_keys\"\n"
            f"sudo -u {user['login']} chmod 600 ~{user['login']}/.ssh/authorized_keys\n"
        )
    log.debug("Generated ssh keys (not shown)")
    return ssh_keys, user_script


def main():
    try:
        os.mkdir('.ssh', 0o700)
    except FileExistsError:
        log.debug("Ignoring .ssh folder exists")

    with open('provision.yml') as file:
        config: dict = yaml.load(file, Loader=yaml.FullLoader)
    log.debug(f"Loaded yml config: {config}")

    region: str = config['region']
    ami_type: str = config['server']['ami_type']
    architecture: str = config['server']['architecture']
    virtualization_type: str = config['server']['virtualization_type']
    ami_name_string: str = f'/aws/service/ami-amazon-linux-latest/{ami_type}-ami-{virtualization_type}-{architecture}-gp2'

    ami_ids: List[str] = get_ami_ids(names=[ami_name_string], region=region)

    if len(ami_ids) > 1:
        log.warning(f"Found {len(ami_ids)} AMI ids that match {ami_name_string}")
    elif not ami_ids:
        log.error("No AMI ids found, cannot continue")
        sys.exit(1)

    ami_id = ami_ids[0]

    user_script: str = f"#!/bin/bash\nsudo groupadd {config['user_group']}\n"
    volumes, user_script = generate_volumes(config, user_script)
    ssh_keys, user_script = generate_ssh_keys(config, user_script)
    log.debug(f"Generated user script {user_script}")

    log.info(f"Creating {config['server']['min_count']} instance(s) using {config['server']['instance_type']}")
    ec2 = boto3.resource('ec2', region_name=region)
    instances: List[object] = ec2.create_instances(
        ImageId=ami_id,
        MinCount=config['server']['min_count'],
        MaxCount=config['server']['max_count'],
        InstanceType=config['server']['instance_type'],
        BlockDeviceMappings=volumes,
        UserData=user_script
    )
    instance: str = instances[0]
    instance.wait_until_running()
    instance.load()
    log.info(f"Instance successfully created as {instance.id}")

    log.info("Saving ssh keys to .ssh")
    ssh_commands: List[str] = []
    for user, ssh_keys in ssh_keys.items():
        key_name = f'id_{user}_{instance.id}'
        with open(f'./.ssh/{key_name}', 'w') as file:
            os.chmod(f'./.ssh/{key_name}', 0o600)
            file.write(ssh_keys['private_key'])

        with open(f'./.ssh/{key_name}.pub', 'w') as file:
            os.chmod(f'./.ssh/{key_name}.pub', 0o600)
            file.write(ssh_keys['public_key'])
        ssh_commands.append(f'ssh -i .ssh/{key_name} {user}@{instance.public_dns_name}')

    print(f"Success! Instance {instance.id} created! Connect to it using the following commands:")
    print('\n'.join(ssh_commands))


if __name__ == '__main__':
    main()
