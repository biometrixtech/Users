from base_test import BaseTest
import boto3

from _user_utils import create_user, delete_user, get_jwt


cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
cognito_user_pool_id = None
for up in cognito_client.list_user_pools(MaxResults=60)['UserPools']:
    if up['Name'] == 'users-dev-users2':
        cognito_user_pool_id = up['Id']

dynamodb_table = boto3.resource('dynamodb').Table('users-dev-users')


class TestUserGet(BaseTest):
    method = 'GET'

    def validate_aws_pre(self):
        cognito_client.admin_get_user(
            UserPoolId=cognito_user_pool_id,
            Username='apitest@fathomai.com'
        )

    def setUp(self):
        delete_user(cognito_user_pool_id)
        user_id = create_user()
        self.endpoint = f'user/{user_id}'

    def tearDown(self):
        delete_user(cognito_user_pool_id)


class TestUserGetInvalidUuid(TestUserGet):
    def setUp(self):
        super().setUp()
        self.endpoint = 'user/notauuid'
    expected_status = [400, 404]


class TestUserGetUnauthorised(TestUserGet):
    def setUp(self):
        super().setUp()
        self.endpoint = 'user/250512fc-f893-4039-aea9-cf50262ef55b'
    expected_status = 401


class TestUserGetUnknownUuid(TestUserGet):
    def setUp(self):
        super().setUp()
        self.endpoint = 'user/250512fc-f893-4039-aea9-cf50262ef55b'
        self.authorization = get_jwt()
    expected_status = 404


class TestUserGetSuccess(TestUserGet):
    expected_status = 200

    def setUp(self):
        super().setUp()
        self.authorization = get_jwt()

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('personal_data', user)
        self.assertIn('email', user['personal_data'])
        self.assertEqual('apitest@fathomai.com', user['personal_data']['email'])


# Don't try to run the abstract base class as a test
del TestUserGet
del BaseTest
