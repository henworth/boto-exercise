# Python AWS Exercise

This repository contains the necessary Python code and provisioning config to create an AWS EC2 instance using Boto.

## Setup Instructions

Ensure AWS credentials are setup via either environment variables or in a file in the default location `~/.aws/credentials`:

```
[default]
aws_access_key_id=HERE
aws_secret_access_key=HERE
```

See [the official documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials) for more information.

Create a Python 3 virtual environment within the cloned repository:

`python -m venv ./venv`

Activate the virtual environment:

`source ./venv/bin/activate`

Install the necessary Python modules:

`pip install -r requirements.txt`

## Script Execution

Once setup has been completed, run the script to create the AWS instance:

`python create_instance.py`

This will load the `provision.yml` file, create SSH keys, and create the instance. SSH keys for any users in the provisioning config will be written to a `.ssh` folder in the local checkout.

Once done, the script will print SSH commands that can be used to connect to the instance, ie.

```
Success! Instance {instance id} created! Connect to it using the following commands:
ssh -i .ssh/id_user1_{instance id} user1@{instance hostname}
ssh -i .ssh/id_user2_{instance id} user2@{instance hostname}
```

## Important Notes

* Each execution of this script will create a new instance. SSH keys will be generated each time and will be unique for each instance.

* This was tested on Python 3.8.5 on Ubuntu 20.04.
