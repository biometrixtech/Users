from base_test import BaseTest
from botocore.exceptions import ClientError
import boto3


cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
cognito_user_pool_id = None
for up in cognito_client.list_user_pools(MaxResults=60)['UserPools']:
    if up['Name'] == 'users-dev-users2':
        cognito_user_pool_id = up['Id']

dynamodb_table = boto3.resource('dynamodb').Table('users-dev-users')


class TestUserCreateNoBody(BaseTest):
    endpoint = 'user'
    method = 'POST'
    body = None
    expected_status = 400


class TestUserCreateNoEmail(BaseTest):
    endpoint = 'user'
    method = 'POST'
    body = {'not_email': 'some_value'}
    expected_status = 400


class TestUserCreateNoPassword(BaseTest):
    endpoint = 'user'
    method = 'POST'
    body = {'personal_data': {'email': 'apitest@fathomai.com'}}
    expected_status = 400


class TestUserCreateInvalidPassword(BaseTest):
    endpoint = 'user'
    method = 'POST'
    body = {'personal_data': {'email': 'apitest@fathomai.com'}, 'password': 'secret'}
    expected_status = 400


class TestUserCreate(BaseTest):
    endpoint = 'user'
    method = 'POST'
    body = {
        "password": 'AbcDef123',
        'personal_data': {
            'email': 'apitest@fathomai.com',
            'first_name': 'John',
            'last_name': 'Smith',
        },
        'agreed_terms_of_use': True,
        'agreed_privacy_policy': True,
    }
    expected_status = 201

    _cognito_id = None

    def validate_aws_pre(self):
        try:
            cognito_client.admin_get_user(
                UserPoolId=cognito_user_pool_id,
                Username='apitest@fathomai.com'
            )
            self.fail('User should not be registered prior to test')
        except ClientError as e:
            if 'UserNotFound' not in str(e):
                self.fail(str(e))

    def validate_aws_post(self):
        cognito_record = cognito_client.admin_get_user(
            UserPoolId=cognito_user_pool_id,
            Username='apitest@fathomai.com'
        )
        self.assertIn('Username', cognito_record)
        self.assertIn('UserAttributes', cognito_record)
        user_attributes = {att['Name']: att['Value'] for att in cognito_record['UserAttributes']}

        self.assertIn('sub', user_attributes)

        self.assertIn('custom:role', user_attributes)
        self.assertEqual('athlete', user_attributes['custom:role'])

        self.assertIn('email', user_attributes)
        self.assertEqual('apitest@fathomai.com', user_attributes['email'])

        ddb_record = dynamodb_table.get_item(Key={'id': cognito_record['Username']})
        self.assertIn('Item', ddb_record)
        ddb_values = ddb_record['Item']

        self.assertIn('personal_data.email', ddb_values)
        self.assertEqual('apitest@fathomai.com', ddb_values['personal_data.email'])

        self.assertNotIn('password', ddb_values)

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('agreed_terms_of_use', user)
        self.assertEqual(user['agreed_terms_of_use'], True)

    def tearDown(self):
        try:
            cognito_client.admin_delete_user(
                UserPoolId=cognito_user_pool_id,
                Username='apitest@fathomai.com'
            )
        except ClientError as e:
            if 'UserNotFoundException' not in str(e):
                raise

