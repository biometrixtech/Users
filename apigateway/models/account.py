from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import random
import re
import string

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException, PaymentRequiredException, InvalidSchemaException

import models.user
import models.account_code


class Account(DynamodbEntity):
    _dynamodb_table_name = Config.get('ACCOUNTS_DYNAMODB_TABLE_NAME')

    def __init__(self, account_id):
        super().__init__({'id': account_id})

    @property
    def id(self):
        return self.primary_key['id']

    def get(self, include_internal_properties=False):
        ret = super().get(include_internal_properties)

        ret['codes'] = {}
        for code in models.account_code.AccountCode.get_many(account_id=self.id):
            ret['codes'][code.role] = code.account_id

        return ret

    def add_user(self, user_id, role):
        """
        Link a user to an account
        :param str user_id:
        :param str role:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')

        prefix = '' if role == 'athlete' else f'{role}_'

        if user_id in self.get()[f'{prefix}users']:
            return

        try:
            upsert = self.DynamodbUpdate()
            upsert.add(f'{prefix}users', {user_id, '_empty'})
            self._update_dynamodb(upsert, Attr('id').exists() & Attr(f'{prefix}users').size().lte(Attr(f'{prefix}seats')))
        except ClientError as e:
            if 'ConditionalCheckFailed' in str(e):
                raise PaymentRequiredException('The maximum number of users has been reached for this account.')
            else:
                print(str(e))
                raise

        self._attributes.setdefault(f'{prefix}users', []).append(user_id)

        models.user.User(user_id).add_account(self.id, role)

    def remove_user(self, user_id, role):
        """
        Unlink a user from an account
        :param str user_id:
        :param str role:
        """
        if not self.exists():
            raise NoSuchEntityException(f'No account with id {self.id}')

        field_name = 'users' if role == 'athlete' else f'{role}_users'

        if user_id not in (self.get()[field_name] or []):
            return

        upsert = self.DynamodbUpdate()
        upsert.delete(field_name, {user_id})
        self._update_dynamodb(upsert, Attr('id').exists())

        self._attributes[field_name].remove(user_id)

        models.user.User(user_id).remove_account(self.id, role)
