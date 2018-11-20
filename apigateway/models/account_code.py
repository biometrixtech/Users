from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import random
import re
import string

from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity
from fathomapi.utils.exceptions import NoSuchEntityException, PaymentRequiredException, InvalidSchemaException

import models.user_data


class AccountCode(DynamodbEntity):
    _dynamodb_table_name = Config.get('ACCOUNTCODES_DYNAMODB_TABLE_NAME')

    def __init__(self, code):
        super().__init__({'code': code})

    @property
    def code(self):
        return self.primary_key['code']

    @property
    def account_id(self):
        return self.get()['account_id']

    @property
    def role(self):
        return self.get()['role']

    @staticmethod
    def generate_code(role):
        """
        Generate random account code of format "ABCD1234"
        """
        allowed_letters = string.ascii_uppercase.replace("O", "")
        allowed_digits = string.digits.replace("0", "")
        signature = {
            'athlete': (4, 4),
            'coach': (6, 4),
        }
        return ''.join(random.choices(allowed_letters, k=signature[role][0])) + ''.join(random.choices(allowed_digits, k=signature[role][1]))
