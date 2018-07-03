#!/usr/bin/python3
from __future__ import print_function
from colorama import Fore
import argparse
import boto3
import sys

iot_client = boto3.client('iot')


def get_certificate_ids(next_token=None):
    params = {'marker': next_token, 'pageSize': 10} if next_token is not None else {'pageSize': 10}
    response = iot_client.list_certificates(**params)
    certificate_ids = [cert['certificateId'] for cert in response['certificates']]
    if 'nextMarker' in response and response['nextMarker'] is not None:
        certificate_ids.extend(get_certificate_ids(response['nextMarker']))
    return certificate_ids


def certificate_has_things(certificate_id):
    certificate_arn = 'arn:aws:iot:us-west-2:887689817172:cert/' + certificate_id
    response = iot_client.list_principal_things(principal=certificate_arn)
    return len(response['things']) > 0


def delete_certificate(certificate_id):
    certificate_arn = 'arn:aws:iot:us-west-2:887689817172:cert/' + certificate_id
    policy_names = [p['policyName'] for p in iot_client.list_attached_policies(target=certificate_arn)['policies']]
    for policy_name in policy_names:
        iot_client.detach_policy(policyName=policy_name, target=certificate_arn)
    iot_client.update_certificate(certificateId=certificate_id, newStatus='INACTIVE')
    iot_client.delete_certificate(certificateId=certificate_id)


def main():
    try:
        certificate_ids = get_certificate_ids()

        for i, certificate_id in enumerate(certificate_ids):
            sys.stdout.write("\033[K")  # Clear the line
            sys.stdout.write("\r    Checking certificate {}/{}".format(i, len(certificate_ids)))
            if not certificate_has_things(certificate_id):
                sys.stdout.write("\033[K")  # Clear the line
                sys.stdout.write("\r    Deleting certificate {}              \n".format(certificate_id))
                delete_certificate(certificate_id)

    finally:
        sys.stdout.write("\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Clean up certificates in IoT which aren't attached to a Thing")
    parser.add_argument('--region',
                        choices=['us-east-1', 'us-west-2'],
                        default='us-west-2',
                        help='AWS Region')

    args = parser.parse_args()

    try:
        main()
    except KeyboardInterrupt:
        print('Exiting', colour=Fore.YELLOW)
        exit(1)
