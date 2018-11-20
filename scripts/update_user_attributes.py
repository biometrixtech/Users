#!/usr/bin/python3
from __future__ import print_function
from colorama import Fore
import argparse
import boto3
import sys

from components.ui import cprint
from components.cognito_user_pool import CognitoUserPool


def main():
    user_pool = CognitoUserPool(f'users-{args.environment}-users')
    user_pool.update_user(args.id, {args.attribute_name: args.attribute_value})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Replace references to a Device Policy")
    parser.add_argument('--region',
                        choices=['us-east-1', 'us-west-2'],
                        default='us-west-2',
                        help='AWS Region')
    parser.add_argument('environment',
                        choices=['dev', 'test', 'production'],
                        help='Environment')
    parser.add_argument('id',
                        help='User ID or email')
    parser.add_argument('attribute_name',
                        help='Attribute to modify')
    parser.add_argument('attribute_value',
                        help='New attribute value')

    args = parser.parse_args()

    try:
        main()
    except KeyboardInterrupt:
        cprint('Exiting', colour=Fore.YELLOW)
        exit(1)
