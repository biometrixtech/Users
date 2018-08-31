from base_test import BaseTest
from botocore.exceptions import ClientError
import boto3
import requests
import os


cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
cognito_user_pool_id = None
for up in cognito_client.list_user_pools(MaxResults=60)['UserPools']:
    if up['Name'] == 'users-dev-users2':
        cognito_user_pool_id = up['Id']

dynamodb_table = boto3.resource('dynamodb').Table('users-dev-users')


class TestUserLogin(BaseTest):
    method = 'POST'
    endpoint = 'user/login'

    def validate_aws_pre(self):
        cognito_client.admin_get_user(
            UserPoolId=cognito_user_pool_id,
            Username='apitest@fathomai.com'
        )

    def setUp(self):
        try:
            cognito_client.admin_get_user(
                UserPoolId=cognito_user_pool_id,
                Username='apitest@fathomai.com'
            )
        except ClientError as e:
            if 'UserNotFound' in str(e):
                requests.post(
                    os.path.join(self.host, 'user'),
                    json={
                        "password": 'AbcDef123',
                        'personal_data': {
                            'email': 'apitest@fathomai.com',
                        },
                        'agreed_terms_of_use': True,
                        'agreed_privacy_policy': True,
                    },
                    headers=self._get_headers()
                )
            else:
                raise

    def tearDown(self):
        try:
            cognito_client.admin_delete_user(
                UserPoolId=cognito_user_pool_id,
                Username='apitest@fathomai.com'
            )
        except ClientError as e:
            if 'UserNotFoundException' not in str(e):
                raise


class TestUserLoginNoBody(TestUserLogin):
    body = None
    expected_status = 400


class TestUserLoginNoEmail(TestUserLogin):
    body = {'not_email': 'some_value'}
    expected_status = 400


class TestUserLoginNoPassword(TestUserLogin):
    body = {'personal_data': {'email': 'apitest@fathomai.com'}}
    expected_status = 400


class TestUserLoginWrongPassword(TestUserLogin):
    body = {'personal_data': {'email': 'apitest@fathomai.com'}, 'password': 'secret'}
    expected_status = 401


class TestUserLoginSuccess(TestUserLogin):
    body = {'personal_data': {'email': 'apitest@fathomai.com'}, 'password': 'AbcDef123'}
    expected_status = 200

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('personal_data', user)
        self.assertIn('email', user['personal_data'])
        self.assertEqual('apitest@fathomai.com', user['personal_data']['email'])


# Don't try to run the abstract base class as a test
del TestUserLogin
del BaseTest
