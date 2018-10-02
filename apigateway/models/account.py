import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException, DuplicateEntityException, PaymentRequiredException


class Account(DynamodbEntity):

    def __init__(self, account_id):
        super().__init__({'id': account_id})

    @property
    def id(self):
        return self.primary_key['id']

    def _get_dynamodb_resource(self):
        return boto3.resource('dynamodb').Table(Config.get('ACCOUNTS_DYNAMODB_TABLE_NAME'))

    def add_user(self, user_id):
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')
        try:
            upsert = self.DynamodbUpdate()
            upsert.add('users', {user_id})
            self._update_dynamodb(upsert, Attr('id').exists() & Attr('users').size().lte(Attr('seats')))
        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise PaymentRequiredException('The maximum number of users has been reached for this account.')
            else:
                print(str(e))
                raise

    def remove_user(self, user_id):
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')
        upsert = self.DynamodbUpdate()
        upsert.delete('users', {user_id})
        self._update_dynamodb(upsert, Attr('id').exists())

    @staticmethod
    def get_from_code(code):
        """
        Get the Account with the given signup code
        :param str code:
        :return: Account
        """
        # TODO
        res = Account(code)
        res.get()
        return Account(code)
