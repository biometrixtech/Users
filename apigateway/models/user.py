import boto3
import json
import os

from models.entity import CognitoEntity

cognito_client = boto3.client('cognito-idp')


class User(CognitoEntity):
    def __init__(self, email):
        super().__init__({'email': email})

    @property
    def username(self):
        return self.primary_key['email']

    @staticmethod
    def schema():
        with open('schemas/user.json', 'r') as f:
            return json.load(f)
        
    @property
    def user_pool_id(self):
        return os.environ['USERS_COGNITO_USER_POOL_ID']
    
    @property
    def user_pool_client_id(self):
        return os.environ['USERS_COGNITO_USER_POOL_CLIENT_ID']
