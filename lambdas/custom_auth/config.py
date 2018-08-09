import boto3
import os
import json
from botocore.exceptions import ClientError


def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    try:
        secret_name = '/'.join(['users', os.environ['ENVIRONMENT'], secret_name])
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise Exception('SecretsManagerError', json.dumps(e.response), 500)
    else:
        if 'SecretString' in get_secret_value_response:
            return json.loads(get_secret_value_response['SecretString'])
        else:
            return get_secret_value_response['SecretBinary']


def load_secrets():
    if 'LAMBDA_TASK_ROOT' in os.environ:
        # Running in AWS Lambda, get secrets from Secrets Manager
        secret_key_base = get_secret("secret_key_base")
        os.environ['SECRET_KEY_BASE'] = secret_key_base['key']
    else:
        from dotenv import load_dotenv
        load_dotenv('.env', verbose=True)
