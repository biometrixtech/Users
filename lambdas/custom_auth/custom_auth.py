from botocore.exceptions import ClientError
from jose import jwt
import datetime
import json
import os
import uuid
import boto3

_secretsmanager_client = boto3.client('secretsmanager')
_secrets = {}


def get_secret(secret_name):
    secret_name = secret_name.lower()
    global _secrets
    if secret_name not in _secrets:
        try:
            get_secret_value_response = _secretsmanager_client.get_secret_value(SecretId=f'users/{os.environ["ENVIRONMENT"]}/{secret_name}')
        except ClientError as e:
            raise Exception('SecretsManagerError', json.dumps(e.response), 500)
        else:
            if 'SecretString' in get_secret_value_response:
                _secrets[secret_name] = json.loads(get_secret_value_response['SecretString'])
            else:
                _secrets[secret_name] = get_secret_value_response['SecretBinary']
    return _secrets[secret_name]


def validate_handler(event, _):
    print(event)

    user_id = get_user_id_from_request(event)

    ret = {"principalId": user_id}
    if 'methodArn' in event:
        ret["policyDocument"] = {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": event['methodArn'].split('/')[0] + '/*',
            }]
        }
    return ret


def service_handler(event, _):
    rs256_key = get_secret('service_jwt_key')

    if os.environ['ENVIRONMENT'] == 'dev':
        delta = datetime.timedelta(days=1)
    else:
        delta = datetime.timedelta(seconds=60)

    token = {
        "auth_time": 1538835893,
        "cognito:username": "00000000-0000-4000-8000-000000000000",
        "custom:role": "service",
        "event_id": str(uuid.uuid4()),
        "iss": os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        "token_use": "id",
        'exp': datetime.datetime.utcnow() + delta,
        'iat': datetime.datetime.utcnow(),
        'sub': '00000000-0000-4000-8000-000000000000',
    }
    print(json.dumps(token))
    return {'token': jwt.encode(token, rs256_key, algorithm='RS256')}


def get_user_id_from_request(event):
    raw_token = event.get('authorizationToken', None)
    if not raw_token:
        raise Exception('Unauthorized')  # No raw token

    try:
        token = jwt.get_unverified_claims(raw_token)
    except Exception:
        raise Exception('Unauthorized')  # Token not a valid JWT

    print(token)
    if 'sub' in token:
        raw_user_id = token['sub']
    elif 'user_id' in token:
        raw_user_id = token['user_id']
    else:
        raise Exception('Unauthorized')  # No user id in token

    if ':' in raw_user_id:
        region, user_id = raw_user_id.split(':', 1)
    else:
        region, user_id = os.environ['AWS_REGION'], raw_user_id

    if region != os.environ['AWS_REGION']:
        raise Exception('Unauthorized')  # Mismatching region
    if not validate_uuid4(user_id):
        raise Exception('Unauthorized')  # Invalid UUID

    if 'exp' not in token:
        raise Exception('No expiry time in token')
    expiry_date = datetime.datetime.fromtimestamp(token['exp'])
    now = datetime.datetime.utcnow()
    if expiry_date < now:
        raise Exception(f'Token has expired: {expiry_date.isoformat()} < {now.isoformat()}')

    return user_id


def validate_uuid4(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False
