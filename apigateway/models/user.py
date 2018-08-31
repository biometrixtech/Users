import boto3
import json
import os

from models.entity import CognitoEntity
from models.user_data import UserData
from utils import metres_to_ftin, kg_to_lb

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

    def get(self):
        ret = super().get()
        ret.update(UserData(ret['id']).get())
        self._munge_response(ret)
        return ret

    def patch(self, body):
        # None of the Cognito attributes are mutable, so we just update the DDB data
        user_data = UserData(self.id)
        ret = user_data.patch(body)
        self._munge_response(ret)
        return ret

    @staticmethod
    def _munge_response(ret):
        ret['biometric_data']['height']['ft_in'] = metres_to_ftin(ret['biometric_data']['height']['m'])
        ret['biometric_data']['weight']['lb'] = metres_to_ftin(ret['biometric_data']['weight']['kg'])
        if 'email' in ret:
            del ret['email']
        return ret

