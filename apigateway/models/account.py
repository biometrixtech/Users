from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import random
import re
import string

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException, PaymentRequiredException, InvalidSchemaException

import models.user_data


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

        if user_id in self.get()['users']:
            return

        try:
            upsert = self.DynamodbUpdate()
            upsert.add('users', {user_id, '_empty'})
            self._update_dynamodb(upsert, Attr('id').exists() & Attr('users').size().lte(Attr('seats')))
        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise PaymentRequiredException('The maximum number of users has been reached for this account.')
            else:
                print(str(e))
                raise

        self._attributes.setdefault('users', []).append(user_id)

        models.user_data.UserData(user_id).add_account(self.id)

    def remove_user(self, user_id):
        """
        Unlink a user from an account
        :param str user_id:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')

        if user_id not in (self.get()['users'] or []):
            return

        upsert = self.DynamodbUpdate()
        upsert.delete('users', {user_id})
        self._update_dynamodb(upsert, Attr('id').exists())

        self._attributes['users'].remove(user_id)

        models.user_data.UserData(user_id).remove_account(self.id)

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
        if not re.match('^[A-NP-Z]{4}[1-9]{4}', code):
            raise InvalidSchemaException('Account code must be four letters followed by four numbers')

        res = Account(None)
        res._secondary_key = {'code': code}
        res._index = 'code'
        try:
            res.get()
            return res
        except NoSuchEntityException:
            raise NoSuchEntityException('No account with that code')
