from abc import abstractmethod
from boto3.dynamodb.conditions import Key, Attr, ConditionExpressionBuilder
from botocore.exceptions import ClientError, ParamValidationError
from decimal import Decimal
from functools import reduce
from operator import iand
import boto3
import datetime
import json

from dynamodbupdate import DynamodbUpdate
from exceptions import InvalidSchemaException, \
    NoSuchEntityException, \
    DuplicateEntityException, \
    ImmutableFieldUpdatedException, \
    InvalidPasswordFormatException, \
    UnauthorizedException, \
    NoUpdatesException


class Entity:

    def __init__(self, primary_key):
        self._primary_key = primary_key

        self._primary_key_fields = list(primary_key.keys())
        self._fields = {}
        schema = self.schema()
        self._load_fields(schema)
        print(self._fields)
        self._exists = None

    def _load_fields(self, schema, parent='', parent_required=True):
        for field, config in schema['properties'].items():
            required = field in schema.get('required', []) and parent_required
            if config['type'] == 'object':
                self._load_fields(config, parent=f'{parent}{field}.', parent_required=required)
            else:
                self._fields[f'{parent}{field}'] = {
                    'immutable': config.get('readonly', False),
                    'required': field in schema.get('required', []) and required,
                    'primary_key': field in self._primary_key_fields,
                    'type': config['type'],
                    'default': config.get('default', None)
                }

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
        if field not in self._fields:
            raise KeyError(field)

        field_type = self._fields[field]['type']
        if isinstance(field_type, dict) and '$ref' in field_type:
            field_type = field_type['$ref']

        if isinstance(field_type, dict) and 'enum' in field_type:
            if value not in field_type['enum']:
                raise ValueError(f'{field} must be one of {field_type["enum"]}, not {value}')
            return value
        elif field_type == 'string':
            return str(value)
        elif field_type == 'number':
            return Decimal(str(value))
        elif field_type == 'bool':
            return bool(value)
        elif field_type == "types.json/definitions/macaddress":
            return str(value).upper()
        else:
            raise NotImplementedError("field_type '{}' cannot be cast".format(field_type))

    def validate(self, operation: str, body: dict):
        # Primary key must be complete
        if None in self.primary_key.values():
            raise InvalidSchemaException('Incomplete primary key')

        body = flatten(body)

        if operation == 'PATCH':
            # Not allowed to modify readonly attributes for PATCH
            for key in self.get_fields(immutable=True, primary_key=False):
                if key in body:
                    raise ImmutableFieldUpdatedException('Cannot modify value of immutable parameter: {}'.format(key))

        else:
            # Required fields must be present for PUT
            for key in self.get_fields(required=True, primary_key=False):
                if key not in body and key not in self.primary_key.keys():
                    raise InvalidSchemaException('Missing required parameter: {}'.format(key))

        for key in self.get_fields(primary_key=False):
            if key in body:
                try:
                    self.cast(key, body[key])
                except ValueError as e:
                    raise InvalidSchemaException(str(e))

    def exists(self):
        if self._exists is None:
            try:
                self.get()
                self._exists = True
            except NoSuchEntityException:
                self._exists = False
        return self._exists

    def get(self):
        fetch_result = self._fetch()

        ret = self.primary_key
        for key in self.get_fields(primary_key=False):
            if key in fetch_result:
                ret[key] = self.cast(key, fetch_result[key])
            else:
                ret[key] = self._fields[key]['default']
        return unflatten(ret)

    @abstractmethod
    def _fetch(self):
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
    _id = None

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

    @property
    def id(self):
        if self._id is None:
            self._fetch()
        return self._id

    def get(self):
        ret = super().get()
        ret['id'] = self._id
        return ret

    def _fetch(self):
        try:
            res = cognito_client.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=self.username,
            )
            self._id = res['Username']
            return {prop['Name'].split(':')[-1]: prop['Value'] for prop in res['UserAttributes']}

        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise

    def patch(self, body):
        self.validate('PATCH', body)
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
        body['updated_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        body['created_date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.validate('PUT', body)

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
            self._fetch()
            return self.id

        except ClientError as e:
            if 'UsernameExistsException' in str(e):
                raise DuplicateEntityException()
            if 'InvalidPasswordException' in str(e):
                raise InvalidPasswordFormatException()
            else:
                print(json.dumps({'exception': str(e)}))
                raise
        except ParamValidationError:
            raise InvalidPasswordFormatException()

    def delete(self):
        try:
            cognito_client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=self.username
            )
        except ClientError as e:
            if 'UserNotFoundException' in str(e):
                raise NoSuchEntityException()
            raise e

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
            if 'NotAuthorizedException' in str(e):
                details = str(e).split(':')[-1].strip(' ')
                raise UnauthorizedException(details)
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
            'session_token': token,
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

    def _fetch(self):
        # And together all the elements of the primary key
        kcx = reduce(iand, [Key(k).eq(v) for k, v in self.primary_key.items()])
        res = self._query_dynamodb(kcx)

        if len(res) == 0:
            raise NoSuchEntityException()
        return res[0]

    def patch(self, body, create=False):
        self.validate('PUT' if create else 'PATCH', body)
        body = flatten(body)

        try:
            upsert = DynamodbUpdate()
            for key in self.get_fields(immutable=None if create else False, primary_key=False):
                if key in body:
                    if self._fields[key]['type'] in ['list', 'object']:
                        upsert.add(key, set(body[key]))
                    elif self._fields[key]['type'] == 'number':
                        upsert.set(key, Decimal(str(body[key])))
                    else:
                        upsert.set(key, body[key])

            print(upsert)
            if len(upsert.parameter_values) == 0:
                raise NoUpdatesException()

            self._get_dynamodb_resource().update_item(
                Key=self.primary_key,
                UpdateExpression=upsert.update_expression,
                ExpressionAttributeNames=upsert.parameter_names,
                ExpressionAttributeValues=upsert.parameter_values,
            )
            # TODO include conditional check if create=False

            return self.get()

        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise DuplicateEntityException()
            else:
                print(str(e))
                raise

    def create(self, body):
        self.patch(body, True)
        return self.primary_key

    @abstractmethod
    def _get_dynamodb_resource(self):
        raise NotImplementedError

    def _query_dynamodb(self, key_condition_expression, limit=10000, scan_index_forward=True, exclusive_start_key=None):
        self._print_condition_expression(key_condition_expression)
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

    @staticmethod
    def _print_condition_expression(expression):
        print(ConditionExpressionBuilder().build_expression(expression, True))


def flatten(d, prefix=''):
    """
    Flatten nested dictionaries
    :param dict d:
    :param str prefix:
    :return:
    """
    return (reduce(
        lambda new_d, kv:
        isinstance(kv[1], dict) and
        {**new_d, **flatten(kv[1], f'{prefix}{kv[0]}.')} or
        {**new_d, f'{prefix}{kv[0]}': kv[1]},
        d.items(),
        {}
    ))


def unflatten(d):
    """
    Unflatten nested dictionaries
    :param dict d:
    :return:
    """
    ret = {}
    for key, value in d.items():
        key_parts = key.split(".")
        d2 = ret
        for part in key_parts[:-1]:
            if part not in d2:
                d2[part] = dict()
            d2 = d2[part]
        d2[key_parts[-1]] = value
    return ret
