#!/usr/bin/python3
from __future__ import print_function
from colorama import Fore
import argparse
import boto3
import sys

iot_client = boto3.client('iot')


def get_certificates_for_policy(policy_name, next_token=None):
    params = {'policyName': policy_name, 'pageSize': 100}
    if next_token is not None:
        params['marker'] = next_token

    response = iot_client.list_targets_for_policy(**params)
    certificate_ids = response['targets']
    if 'nextMarker' in response and response['nextMarker'] is not None:
        certificate_ids.extend(get_certificates_for_policy(policy_name, response['nextMarker']))
    return certificate_ids


def swap_policy(certificate_id, old_policy_name, new_policy_name):
    iot_client.attach_policy(policyName=new_policy_name, target=certificate_id)
    iot_client.detach_policy(policyName=old_policy_name, target=certificate_id)


def main():
    try:
        certificate_ids = get_certificates_for_policy(args.old_policy)

        for i, certificate_id in enumerate(certificate_ids):
            sys.stdout.write("\033[K")  # Clear the line
            sys.stdout.write("\r    Updating certificate {}/{}".format(i, len(certificate_ids)))
            swap_policy(certificate_id, args.old_policy, args.new_policy)

        iot_client.delete_policy(policyName=args.old_policy)

    finally:
        sys.stdout.write("\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Replace references to a Device Policy")
    parser.add_argument('--region',
                        choices=['us-east-1', 'us-west-2'],
                        default='us-west-2',
                        help='AWS Region')
    parser.add_argument('old_policy',
                        help='old policy ID')
    parser.add_argument('new_policy',
                        help='new policy ID')

    args = parser.parse_args()

    try:
        main()
    except KeyboardInterrupt:
        print('Exiting', colour=Fore.YELLOW)
        exit(1)
