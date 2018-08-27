import boto3
import json
import os

from models.entity import DynamodbEntity


class UserData(DynamodbEntity):

    def __init__(self, user_id, updated_date=None):
        super().__init__({'user_id': user_id})
        self._updated_date = updated_date

    @property
    def user_id(self):
        return self.primary_key['user_id']

    def _get_dynamodb_resource(self):
        return boto3.resource('dynamodb').Table(os.environ['DYNAMODB_USERS_TABLE_NAME'])

    @staticmethod
    def schema():
        with open('schemas/user_data.json', 'r') as f:
            return json.load(f)
