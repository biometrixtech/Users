import boto3

_cognito_client = boto3.client('cognito-idp')


class CognitoUserPool:
    _id = None

    def __init__(self, name):
        self._name = name

    @property
    def name(self):
        return self._name

    @property
    def id(self):
        if self._id is None:
            for up in self._get_all_user_pools():
                if up['Name'] == self._name:
                    self._id = up['Id']
                    break
            else:
                raise Exception(f'Cognito User Pool {self.name} was not found')
        return self._id

    def _get_all_user_pools(self, next_token=None):
        args = {'MaxResults': 60}
        if next_token is not None:
            args['NextToken'] = next_token

        res = _cognito_client.list_user_pools(**args)

        ret = res['UserPools']
        if 'NextToken' in res:
            ret += self._get_all_user_pools(res['NextToken'])

        return ret

    def update_user(self, user_id, attributes):
        attributes_to_delete = []
        attributes_to_update = []

        for key, value in attributes.items():
                param_name = key if key in ['email_verified'] else f'custom:{key}'
                if value is None:
                    attributes_to_delete.append(param_name)
                else:
                    attributes_to_update.append({'Name': param_name, 'Value': value})

        _cognito_client.admin_update_user_attributes(
            UserPoolId=self.id,
            Username=user_id,
            UserAttributes=attributes_to_update
        )
        _cognito_client.admin_delete_user_attributes(
            UserPoolId=self.id,
            Username=user_id,
            UserAttributeNames=attributes_to_delete
        )
