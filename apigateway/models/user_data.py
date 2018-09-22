import boto3
import json
import os

from ._dynamodb_entity import DynamodbEntity


class UserData(DynamodbEntity):

    def __init__(self, user_id):
        super().__init__({'id': user_id})

    @property
    def user_id(self):
        return self.primary_key['id']

    def _get_dynamodb_resource(self):
        return boto3.resource('dynamodb').Table(os.environ['USERS_DYNAMODB_TABLE_NAME'])

    @staticmethod
    def schema():
        with open('schemas/user_data.json', 'r') as f:
            return json.load(f)
