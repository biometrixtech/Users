from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import random
import string

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException, PaymentRequiredException


class Account(DynamodbEntity):
    _dynamodb_table_name = Config.get('ACCOUNTS_DYNAMODB_TABLE_NAME')

    def __init__(self, account_id):
        super().__init__({'id': account_id})

    @property
    def id(self):
        return self.primary_key['id']

    def add_user(self, user_id):
        """
        Link a user to an account
        :param str user_id:
        """
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
        """
        Unlink a user from an account
        :param str user_id:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')
        upsert = self.DynamodbUpdate()
        upsert.delete('users', {user_id})
        self._update_dynamodb(upsert, Attr('id').exists())

    @staticmethod
    def generate_code():
        """
        Generate random account code of format "ABCD1234"
        """
        allowed_letters = string.ascii_uppercase.replace("O", "")
        allowed_digits = string.digits.replace("0", "")
        return ''.join(random.choices(allowed_letters, k=4)) + ''.join(random.choices(allowed_digits, k=4))

    @staticmethod
    def new_from_code(code):
        """
        Get the Account with the given signup code
        :param str code:
        :return: Account
        """
        res = Account(code)
        res._primary_key = {'code': code}
        res._index = 'code'
        try:
            res.get()
            res._primary_key = {'id': res.id}
            res._index = None
            return res
        except NoSuchEntityException:
            raise NoSuchEntityException('No account with that code')
