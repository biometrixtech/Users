from abc import abstractmethod
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from decimal import Decimal
from functools import reduce
from operator import iand
import boto3
import datetime
import json

from dynamodbupdate import DynamodbUpdate
from exceptions import InvalidSchemaException, NoSuchEntityException, DuplicateEntityException, ApplicationException


class Entity:

    def __init__(self, primary_key):
        self._primary_key = primary_key

        self._primary_key_fields = list(primary_key.keys())
        self._fields = {}
        schema = self.schema()
        for field, config in schema['properties'].items():
            self._fields[field] = {
                'immutable': config.get('readonly', False),
                'required': field in schema['required'],
                'primary_key': field in self._primary_key_fields
            }

        self._exists = None

    @property
    def primary_key(self):
        return self._primary_key

    @staticmethod
    @abstractmethod
    def schema():
        raise NotImplementedError

    def get_fields(self, *, immutable=None, required=None, primary_key=None):
        return [
            k for k, v in self._fields.items()
            if (immutable is None or v['immutable'] == immutable)
            and (required is None or v['required'] == required)
            and (primary_key is None or v['primary_key'] == primary_key)
        ]

    def cast(self, field, value):
        schema = self.schema()
        if field not in schema['properties']:
            raise KeyError(field)

        field_type = schema['properties'][field]['type']
        if isinstance(field_type, dict) and '$ref' in field_type:
            field_type = field_type['$ref']

        if field_type == 'string':
            return str(value)
        elif field_type == 'number':
            return Decimal(str(value))
        elif field_type == "types.json/definitions/macaddress":
            return str(value).upper()
        else:
            raise NotImplementedError("field_type '{}' cannot be cast".format(field_type))

    def validate(self, operation, body):
        # Primary key must be complete
        if None in self.primary_key.values():
            raise InvalidSchemaException('Incomplete primary key')

        if operation == 'PATCH':
            # Not allowed to modify readonly attributes for PATCH
            for key in self.get_fields(immutable=True, primary_key=False):
                if key in body:
                    raise InvalidSchemaException('Cannot modify value of immutable parameter: {}'.format(key))

        else:
            # Required fields must be present for PUT
            for key in self.get_fields(required=True, primary_key=False):
                if key not in body and key not in self.primary_key.keys():
                    raise InvalidSchemaException('Missing required parameter: {}'.format(key))

    def exists(self):
        if self._exists is None:
            try:
                self.get()
                self._exists = True
            except NoSuchEntityException:
                self._exists = False
        return self._exists

    @abstractmethod
    def get(self):
        raise NotImplementedError()

    @abstractmethod
    def create(self, body):
        raise NotImplementedError()

    @abstractmethod
    def patch(self, body):
        raise NotImplementedError()

    @abstractmethod
    def delete(self):
        raise NotImplementedError()


cognito_client = boto3.client('cognito-idp')


class CognitoEntity(Entity):

    @property
    @abstractmethod
    def username(self):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def schema():
        raise NotImplementedError
    
    @property
    @abstractmethod
    def user_pool_id(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def user_pool_client_id(self):
        raise NotImplementedError

    def get(self):
        try:
            res = cognito_client.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=self.username,
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise

        custom_properties = {prop['Name'].split(':')[-1]: prop['Value'] for prop in res['UserAttributes']}

        ret = self.primary_key
        for key in self.get_fields(primary_key=False):
            if key in custom_properties:
                ret[key] = self.cast(key, custom_properties[key])
            else:
                ret[key] = self.schema()['properties'][key].get('default', None)
        return ret

    def patch(self, body):
        attributes_to_update = []
        attributes_to_delete = []
        for key in self.get_fields(immutable=False, primary_key=False):
            if key in body:
                if body[key] is None:
                    attributes_to_delete.append('custom:{}'.format(key))
                else:
                    attributes_to_update.append({'Name': 'custom:{}'.format(key), 'Value': str(body[key])})

        if self.exists():
            cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                UserAttributes=attributes_to_update
            )
            cognito_client.admin_delete_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                UserAttributeNames=attributes_to_delete
            )
        else:
            # TODO
            raise NotImplementedError

        return self.get()

    def create(self, body):
        body['mac_address'] = self.username
        for key in self.get_fields(required=True):
            if key not in body:
                raise InvalidSchemaException('Missing required request parameters: {}'.format(key))
        try:
            cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=self.username,
                TemporaryPassword=body['password'],
                UserAttributes=[
                    {'Name': 'custom:{}'.format(key), 'Value': body[key]}
                    for key in self.get_fields(primary_key=False)
                    if key in body
                ],
                MessageAction='SUPPRESS',
            )
            return self.get()

        except ClientError as e:
            if 'UsernameExistsException' in str(e):
                raise DuplicateEntityException()
            else:
                print(json.dumps({'exception': str(e)}))
                raise

    def login(self, *, password=None, token=None):
        if not self.exists():
            raise NoSuchEntityException()

        if password is not None:
            return self._login_password(password)
        elif token is not None:
            return self._login_token(token)
        else:
            raise Exception('Either password or token must be given')

    def _login_password(self, password):
        try:
            response = cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': self.username,
                    'PASSWORD': password
                },
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise
        if 'ChallengeName' in response and response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
            # Need to set a new password
            response = cognito_client.admin_respond_to_auth_challenge(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={'USERNAME': self.username, 'NEW_PASSWORD': password},
                Session=response['Session']
            )

        expiry_date = datetime.datetime.now() + datetime.timedelta(seconds=response['AuthenticationResult']['ExpiresIn'])
        return {
            'jwt': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': response['AuthenticationResult']['RefreshToken'],
        }

    def _login_token(self, token):
        try:
            response = cognito_client.admin_initiate_auth(
                UserPoolId=self.user_pool_id,
                ClientId=self.user_pool_client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'USERNAME': self.username,
                    'REFRESH_TOKEN': token
                },
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise
        if 'ChallengeName' in response and response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
            # Need to set a new password
            raise Exception('Cannot refresh credentials, need to reset password')

        expiry_date = datetime.datetime.now() + datetime.timedelta(seconds=response['AuthenticationResult']['ExpiresIn'])
        return {
            'jwt': response['AuthenticationResult']['AccessToken'],
            'expires': expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'session_token': response['AuthenticationResult']['RefreshToken'],
        }

    def logout(self):
        try:
            cognito_client.admin_user_global_sign_out(
                UserPoolId=self.user_pool_id,
                Username=self.username,
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise


class DynamodbEntity(Entity):

    def get(self):
        # And together all the elements of the primary key
        kcx = reduce(iand, [Key(k).eq(v) for k, v in self.primary_key.items()])
        res = self._query_dynamodb(kcx)

        if len(res) == 0:
            raise NoSuchEntityException()
        return res[0]

    def patch(self, body, create=False):
        self.validate('PATCH', body)

        try:
            upsert = DynamodbUpdate()
            for key in self.get_fields(immutable=None if create else False, primary_key=False):
                if key in body:
                    if self.schema()['properties'][key]['type'] in ['list', 'object']:
                        upsert.add(key, set(body[key]))
                    else:
                        upsert.set(key, body[key])

            self._get_dynamodb_resource().update_item(
                Key=self.primary_key,
                UpdateExpression=upsert.update_expression,
                ExpressionAttributeValues=upsert.parameters,
            )
            # TODO include conditional check if create=False

            return self.get()

        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise DuplicateEntityException()
            else:
                print(json.dumps({'exception': e}))
                raise

    def create(self, body):
        self.validate('PUT', body)
        return self.patch(body, True)

    @abstractmethod
    def _get_dynamodb_resource(self):
        raise NotImplementedError

    def _query_dynamodb(self, key_condition_expression, limit=10000, scan_index_forward=True, exclusive_start_key=None):
        if exclusive_start_key is not None:
            ret = self._get_dynamodb_resource().query(
                Select='ALL_ATTRIBUTES',
                Limit=limit,
                KeyConditionExpression=key_condition_expression,
                ExclusiveStartKey=exclusive_start_key,
                ScanIndexForward=scan_index_forward,
            )
        else:
            ret = self._get_dynamodb_resource().query(
                Select='ALL_ATTRIBUTES',
                Limit=limit,
                KeyConditionExpression=key_condition_expression,
                ScanIndexForward=scan_index_forward,
            )
        if 'LastEvaluatedKey' in ret:
            # There are more records to be scanned
            return ret['Items'] + self._query_dynamodb(key_condition_expression, limit, scan_index_forward, ret['LastEvaluatedKey'])
        else:
            # No more items
            return ret['Items']
