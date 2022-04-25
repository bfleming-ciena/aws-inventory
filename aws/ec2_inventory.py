from sqlite3 import dbapi2
import ipdb
import boto3
import csv
from botocore.exceptions import ClientError

ORG_ACCOUNT = ''
ALLOWED_REGIONS = ["us-west-2"]
ACCOUNT_FILTER = [""]
SKIP_ACCOUNT = [""]
# ListAWSAccountsFromOrganization
ORG_ACCOUNT_ROLE = "OrganizationAccountAccessRole"
# ReadOnlyCrossAccountAccess
CROSS_ACCOUNT_READ_ROLE = "OrganizationAccountAccessRole"
COLS = []


def main():
    account_list = get_all_accounts()
    ec2_inventory = dict()

    # Checking your accounts
    for account in account_list:
        region_client = get_aws_client(
            client_type="ec2", account=account['Id'], region="us-east-1", rolename=CROSS_ACCOUNT_READ_ROLE
        )
        ec2_regions = get_regions(region_client)

        # Every region oin the account.  You can override to do a subset.
        for region in ec2_regions:
            print("Checking %s in %s" % (account['Id'], region))

            ec2_client = get_aws_client(
                client_type="ec2", account=account['Id'], region=region, rolename=CROSS_ACCOUNT_READ_ROLE
            )

            # Returns all instances at this stage. It is the full instance datastructure
            ec2_instances = get_instances(ec2_client)
            print("Found %s instances in account %s %s" %
                  (len(ec2_instances), account['Id'], region))
            # Add the instances to our inventory
            for ec2_instance in ec2_instances:

                # Check for public IP.
                public_ip = ec2_instance['PublicIpAddress'] if "PublicIpAddress" in ec2_instance.keys(
                ) else "NA"

                # Note inventory is a dict with the instance id as the key
                ec2_inventory[ec2_instance['InstanceId']] = {
                    'AccountName': account['Name'],
                    'AccountId': account['Id'],
                    'InstanceTagName': get_instance_tag(ec2_instance, "Name"),
                    'InstanceId': ec2_instance['InstanceId'],
                    'AvailabilityZone': ec2_instance['Placement']['AvailabilityZone'],
                    'PrivateIpAddress': ec2_instance['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['PrivateIpAddress'],
                    'PublicIpAddress': public_ip,
                    'HostName': "NA",  # Need SSM for these. Coming up next...
                    'OperatingSystem': "NA"
                }

            # Complete the picture in our inventory for all instances that have SSM enabled.
            ssm_client = get_aws_client(
                client_type="ssm", account=account['Id'], region=region, rolename=CROSS_ACCOUNT_READ_ROLE)

            ssm_instances = get_ssm_instances(ssm_client)

            # Inventory is key'ed on instance ID. Just add these ssm-aware fields to our instance inventory
            for ssm_instance in ssm_instances:

                if ssm_instance[0]['InstanceId'] in ec2_inventory:
                    ec2_inventory[ssm_instance[0]['InstanceId']
                                  ]['HostName'] = ssm_instance[0]['ComputerName']

                    ec2_inventory[ssm_instance[0]['InstanceId']
                                  ]['OperatingSystem'] = ssm_instance[0]['PlatformName']

    write_csv("ec2_inventory.csv", ec2_inventory)
    print("Writing %s records to ec2_inventory.csv" % (len(ec2_inventory)))


def get_all_accounts():
    account_list = []
    org_client = get_aws_client(
        client_type="organizations", account=ORG_ACCOUNT, region="us-east-1", rolename=ORG_ACCOUNT_ROLE
    )

    org_paginator = org_client.get_paginator('list_accounts')
    org_iterator = org_paginator.paginate()

    for accounts in org_iterator:
        for account in accounts['Accounts']:
            if account['Status'] == 'ACTIVE':
                account_list.append(account)

    # Allows user to specify the specific accounts to search rather than all.
    # Helps with testing
    if ACCOUNT_FILTER:
        accounts_filtered = [
            a for a in account_list if(a['Id'] in ACCOUNT_FILTER and a['Id'] not in SKIP_ACCOUNT)]
        return accounts_filtered

    return account_list


def get_aws_client(region="us-east-1", client_type="ec2", account="", rolename=CROSS_ACCOUNT_READ_ROLE):

    credentials = assume_role(
        account,
        "{account}{client_type}".format(
            account=account, client_type=client_type),
        role_name=rolename,
    )

    client = boto3.client(client_type, region_name=region, **credentials)

    return client


def get_regions(client):

    ec2_regions = [region['RegionName']
                   for region in client.describe_regions()['Regions'] if region['RegionName'] in ALLOWED_REGIONS]

    return ec2_regions


def write_csv(filename, ec2_inventory):
    # Set First Colum for Instance ID
    COLS.append('ResourceId')

    # Add Keys to be Columnns
    for key in ec2_inventory:
        # Dynamically ADD Rest of Column Headings
        for item in ec2_inventory[key]:
            if item not in COLS:
                COLS.append(item)

    # Open CSV For Writing Data
    with open(filename, 'w', newline='') as myfile:
        writer = csv.writer(myfile, delimiter=',')
        writer.writerow(COLS)
        for data in ec2_inventory:
            # Add the ID of the Instance as the first item
            row = [data]
            listof_columns = ec2_inventory[data]

            # Write Data to CSV
            itercols = iter(COLS)
            next(itercols)
            for col in itercols:
                if col in listof_columns:
                    row.append(listof_columns[col])
                else:
                    row.append("")
            writer.writerow(row)


def get_instance_tag(ec2_instance, tagname):
    if "Tags" in ec2_instance:
        for tag in ec2_instance['Tags']:
            if tagname in tag['Key']:
                return tag['Value']


def get_instances(ec2_client):
    paginator = ec2_client.get_paginator('describe_instances')

    response_iterator = paginator.paginate(
        Filters=[
            {
                'Name': 'instance-state-name',
                'Values': ['running', 'stopped']
            }]
    )

    ec2_instances = []
    for reservations in response_iterator:
        for instances in reservations['Reservations']:
            ec2_instances.append(instances['Instances'][0])

    return ec2_instances

# The role must exist in the cross account.
# Your current account must allow assume role,
# The cross account role IAM policy must grant access to the resource (s3, etc..)


def assume_role(
    account_id, role_session_name, role_name=CROSS_ACCOUNT_READ_ROLE
):
    """
    Assumes the role in the specificed account, and returns a dict that
    can in turn be passed into the boto3.client method when needed.
    """

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        sts = boto3.client("sts")
        assumedRoleObject = sts.assume_role(
            RoleArn=role_arn, RoleSessionName=role_session_name, DurationSeconds=900
        )
    except ClientError as ex:
        print(f"Cannot assume {role_name} for account {account_id}!")
        print(f"{ex}")
        return None

    # Make these easier to use by further calls to boto3.
    credentials = assumedRoleObject["Credentials"]

    boto_style_credentials = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    return boto_style_credentials


def get_ssm_instances(client):
    paginator = client.get_paginator('get_inventory')
    response_iterator = paginator.paginate()

    instances = []

    for inventory in response_iterator:
        for entity in inventory['Entities']:
            try:
                instance = entity['Data']['AWS:InstanceInformation']['Content'][0]

                # Skip Terminated Instances
                if instance.get('InstanceStatus') == 'Stopped' or instance.get('InstanceStatus') == 'Running':
                    instances.append(
                        entity['Data']['AWS:InstanceInformation']['Content'])
                else:
                    print("Skipping... %s" % instance.get('InstanceId'))

            except (KeyError, ValueError):
                continue
    return instances


main()
