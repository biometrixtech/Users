import jwt
import os
from uuid import UUID


def handler(event, _):
    print(event)

    user_id = get_user_id_from_request(event)

    return {
        "principalId": user_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": event['methodArn'].split('/')[0] + '/*',
            }]
        }
    }


def get_user_id_from_request(event):
    raw_token = event.get('authorizationToken', None)
    if not raw_token:
        raise Exception('Unauthorized')  # No raw token

    try:
        token = jwt.decode(raw_token, verify=False)
        validate_token(token)
    except:
        raise Exception('Unauthorized')  # Token not a valid JWT

    raw_user_id = token.get('sub', ':')
    if not raw_user_id or ':' not in raw_user_id:
        # Support legacy JWTs from Ruby API
        if 'user_id' in token:
            raw_user_id = '{}:{}'.format(os.environ['AWS_REGION'], token['user_id'])
        else:
            raise Exception('Unauthorized')  # Invalid raw_user_id

    region, user_id = raw_user_id.split(':', 1)
    if region != os.environ['AWS_REGION']:
        raise Exception('Unauthorized')  # Mismatching region
    if not validate_uuid4(user_id):
        raise Exception('Unauthorized')  # Invalid UUID

    return user_id


def validate_token(token):
    # TODO!!
    pass


def validate_uuid4(uuid_string):
    try:
        val = UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False
