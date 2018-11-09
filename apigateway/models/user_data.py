from boto3.dynamodb.conditions import Attr

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException

import models.account


class UserData(DynamodbEntity):
    _dynamodb_table_name = Config.get('USERS_DYNAMODB_TABLE_NAME')

    def __init__(self, user_id):
        super().__init__({'id': user_id})

    @property
    def id(self):
        return self.primary_key['id']

    def add_account(self, account_id):
        """
        Link the user to an account
        :param str account_id:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No user with id {self.id}')

        if account_id in self.get()['account_ids']:
            return

        upsert = self.DynamodbUpdate()
        upsert.add('account_ids', {account_id, '_empty'})
        self._update_dynamodb(upsert, Attr('id').exists())

        self._attributes.setdefault('account_ids', []).append(account_id)

        models.account.Account(account_id).add_user(self.id)

    def remove_account(self, account_id):
        """
        Unlink the user from an account
        :param str account_id:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No user with id {self.id}')

        if account_id not in (self.get()['account_ids'] or []):
            return

        upsert = self.DynamodbUpdate()
        upsert.delete('account_ids', {account_id})
        self._update_dynamodb(upsert, Attr('id').exists())

        self._attributes['account_ids'].remove(account_id)

        models.account.Account(account_id).add_user(self.id)
