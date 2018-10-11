import boto3

from fathomapi.api.config import Config
from fathomapi.models.cognito_entity import CognitoEntity
from fathomapi.utils.exceptions import UnauthorizedException

from models.user_data import UserData
from utils import metres_to_ftin, kg_to_lb

_cognito_client = boto3.client('cognito-idp')


class User(CognitoEntity):
    def __init__(self, email):
        super().__init__({'email': email})
        self._id = email

    @classmethod
    def user_pool_id(cls):
        return Config.get('USERS_COGNITO_USER_POOL_ID')

    @classmethod
    def user_pool_client_id(cls):
        return Config.get('USERS_COGNITO_USER_POOL_CLIENT_ID')

    def get(self):
        ret = super().get()
        ret.update(UserData(ret['id']).get())
        self._munge_response(ret)
        return ret

    def patch(self, body):
        super().patch(body)
        user_data = UserData(self.id)
        ret = user_data.patch(body)
        self._munge_response(ret)
        return ret

    @staticmethod
    def _munge_response(ret):
        ret['biometric_data']['height']['ft_in'] = metres_to_ftin(ret['biometric_data']['height']['m'])
        ret['biometric_data']['mass']['lb'] = kg_to_lb(ret['biometric_data']['mass']['kg'])
        if 'email' in ret:
            del ret['email']
        return ret

    def change_password(self, session_token, old_password, new_password):
        auth = self._login_token(session_token)
        _cognito_client.change_password(
            AccessToken=auth['access_token'],
            PreviousPassword=old_password,
            ProposedPassword=new_password,
        )

    def send_password_reset(self):
        _cognito_client.forgot_password(
            ClientId=self.user_pool_client_id(),
            Username=self.id
        )

    def reset_password(self, confirmation_code, password):
        _cognito_client.confirm_forgot_password(
            ClientId=self.user_pool_client_id(),
            Username=self.id,
            ConfirmationCode=confirmation_code,
            Password=password
        )

    def verify_email(self, confirmation_code):
        if self.get()['email_confirmation_code'] == confirmation_code:
            self._patch(
                ['email_verified', 'email_confirmation_code'],
                {'email_verified': 'true', 'email_confirmation_code': None}
            )
        else:
            raise UnauthorizedException('Incorrect Confirmation Code')
