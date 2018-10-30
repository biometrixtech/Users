from fathomapi.api.config import Config
from fathomapi.models.dynamodb_entity import DynamodbEntity


class UserData(DynamodbEntity):
    _dynamodb_table_name = Config.get('USERS_DYNAMODB_TABLE_NAME')

    def __init__(self, user_id):
        super().__init__({'id': user_id})

    @property
    def user_id(self):
        return self.primary_key['id']
