import boto3
from boto3.dynamodb.conditions import Attr

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity


class Account(DynamodbEntity):

    def __init__(self, account_id):
        super().__init__({'id': account_id})

    @property
    def id(self):
        return self.primary_key['id']

    def _get_dynamodb_resource(self):
        return boto3.resource('dynamodb').Table(Config.get('ACCOUNTS_DYNAMODB_TABLE_NAME'))

    def add_user(self, user_id):
        self.patch({'users': [user_id]}, create=False, condition=Attr('users').size().lt(Attr('seats')))

    def remove_user(self, user_id):
        self.patch({'¬users': [user_id]}, create=False)

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
