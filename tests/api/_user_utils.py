import boto3
from botocore.exceptions import ClientError
import requests
import datetime

cognito_client = boto3.client('cognito-idp', region_name='us-west-2')


def delete_user(cognito_user_pool_id):
    try:
        cognito_client.admin_delete_user(
            UserPoolId=cognito_user_pool_id,
            Username='apitest@fathomai.com'
        )
    except ClientError as e:
        if 'UserNotFoundException' not in str(e):
            raise


def create_user():
    res = requests.post(
        'https://apis.dev.fathomai.com/users/latest/user',
        json={
            "password": 'AbcDef123',
            'personal_data': {
                'email': 'apitest@fathomai.com',
            },
            'agreed_terms_of_use': True,
            'agreed_privacy_policy': True,
        },
        headers={
            'Accept': 'application/json',
            'User-Agent': 'biometrix apitest',
        }
    )
    if res.status_code != 201:
        raise AssertionError(f'Could not create user: {res.status_code}: {res.text}')

    return res.json()['user']['id']


def get_jwt():
    res = requests.post(
        'https://apis.dev.fathomai.com/users/latest/user/login',
        json={
            "password": 'AbcDef123',
            'personal_data': {
                'email': 'apitest@fathomai.com',
            },
        },
        headers={
            'Accept': 'application/json',
            'User-Agent': 'biometrix apitest',
        }
    )
    if res.status_code != 200:
        raise AssertionError(f'Could not login user: {res.status_code}: {res.text}')

    return res.json()['authorization']['jwt']
