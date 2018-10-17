from decimal import Decimal

from base_test import BaseTest
import boto3

from _user_utils import create_user, delete_user, get_jwt


cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
cognito_user_pool_id = None
for up in cognito_client.list_user_pools(MaxResults=60)['UserPools']:
    if up['Name'] == 'users-dev-users2':
        cognito_user_pool_id = up['Id']

dynamodb_table = boto3.resource('dynamodb').Table('users-dev-users')


class TestUserPatch(BaseTest):
    method = 'PATCH'
    body = {}

    def validate_aws_pre(self):
        cognito_client.admin_get_user(
            UserPoolId=cognito_user_pool_id,
            Username='apitest@fathomai.com'
        )

    def setUp(self):
        delete_user(cognito_user_pool_id)
        self.user_id = create_user()
        self.endpoint = f'user/{self.user_id}'
        self.authorization = get_jwt()

    def tearDown(self):
        delete_user(cognito_user_pool_id)


class TestUserPatchInvalidUuid(TestUserPatch):
    def setUp(self):
        super().setUp()
        self.endpoint = 'user/notauuid'
    expected_status = [400, 404]


class TestUserPatchNoJwt(TestUserPatch):
    def setUp(self):
        super().setUp()
        self.authorization = None
    expected_status = 401


class TestUserPatchInvalidJwt(TestUserPatch):
    def setUp(self):
        super().setUp()
        self.authorization = 'notajwt'
    expected_status = 401


class TestUserPatchUnknownUuid(TestUserPatch):
    def setUp(self):
        super().setUp()
        self.endpoint = 'user/250512fc-f893-4039-aea9-cf50262ef55b'
    expected_status = 404


class TestUserPatchChangeEmail(TestUserPatch):
    body = {'personal_data': {'email': 'apitest2@fathomai.com'}}
    expected_status = 422


class TestUserPatchChangeRole(TestUserPatch):
    body = {'role': 'admin'}
    expected_status = [400, 401, 403]


class TestUserPatchNoUpdates(TestUserPatch):
    body = {'notavalidkey': 'irrelevantvalue'}
    expected_status = 204


class TestUserPatchSuccess(TestUserPatch):
    body = {'agreed_terms_of_use': False}
    expected_status = 200
    ddb_field = None
    ddb_value_pre = None
    ddb_value_post = None

    def setUp(self):
        super().setUp()
        self.authorization = get_jwt()

    def validate_aws_pre(self):
        ddb_record = dynamodb_table.get_item(Key={'id': self.user_id})
        self.assertIn('Item', ddb_record)
        ddb_values = ddb_record['Item']

        self.assertIn('personal_data.email', ddb_values)
        self.assertEqual('apitest@fathomai.com', ddb_values['personal_data.email'])

        if self.ddb_field in ddb_values:
            self.assertEqual(self.ddb_value_pre, ddb_values[self.ddb_field])
        elif self.ddb_value_pre is not None:
            self.fail(f'{self.ddb_field} not found in {ddb_values}')

    def validate_aws_post(self):
        ddb_record = dynamodb_table.get_item(Key={'id': self.user_id})
        self.assertIn('Item', ddb_record)
        ddb_values = ddb_record['Item']

        self.assertIn('personal_data.email', ddb_values)
        self.assertEqual('apitest@fathomai.com', ddb_values['personal_data.email'])

        self.assertIn(self.ddb_field, ddb_values)
        self.assertEqual(self.ddb_value_post, ddb_values[self.ddb_field])


class TestUserPatchSuccessChangeTermsOfUse(TestUserPatchSuccess):
    body = {'agreed_terms_of_use': False}
    ddb_field = 'agreed_terms_of_use'
    ddb_value_pre = True
    ddb_value_post = False

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('agreed_terms_of_use', user)
        self.assertEqual(False, user['agreed_terms_of_use'])


class TestUserPatchSuccessChangeHeight(TestUserPatchSuccess):
    body = {'biometric_data': {'height': {'m': 1.2}}}
    ddb_field = 'biometric_data.height.m'
    ddb_value_pre = None
    ddb_value_post = Decimal('1.2')

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('biometric_data', user)
        self.assertIn('height', user['biometric_data'])
        self.assertIn('m', user['biometric_data']['height'])
        self.assertEqual(1.2, user['biometric_data']['height']['m'])


class TestUserPatchSuccessChangeHeightImperial(TestUserPatchSuccess):
    body = {'biometric_data': {'height': {'ft_in': [6, 1]}}}
    ddb_field = 'biometric_data.height.m'
    ddb_value_pre = None
    ddb_value_post = Decimal('1.854')

    def validate_response(self, body, headers, status):
        self.assertIn('user', body)
        user = body['user']
        self.assertIn('biometric_data', user)
        self.assertIn('height', user['biometric_data'])
        self.assertIn('m', user['biometric_data']['height'])
        self.assertEqual(1.854, user['biometric_data']['height']['m'])
        self.assertIn('ft_in', user['biometric_data']['height'])
        self.assertEqual([6, 1], user['biometric_data']['height']['ft_in'])


# Don't try to run the abstract base class as a test
del TestUserPatchSuccess
del TestUserPatch
del BaseTest
