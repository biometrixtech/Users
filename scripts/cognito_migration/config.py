from pymongo import MongoClient
import os
import boto3
import json
from botocore.exceptions import ClientError
from exceptions import ApplicationException

global DATABASE


def get_mongo_collection(collection):
    try:
        mongo_collection = os.environ['MONGO_COLLECTION_' + collection.upper()]
    except KeyError:
        mongo_collection = collection
    database = get_mongo_database()
    collection = database[mongo_collection]

    return collection


def get_mongo_database():
    config = get_secret('mongo')
    os.environ["MONGO_HOST"] = config['host']
    os.environ["MONGO_REPLICASET"] = config['replicaset']
    os.environ["MONGO_DATABASE"] = config['database']
    os.environ["MONGO_USER"] = config['user']
    os.environ["MONGO_PASSWORD"] = config['password']
    os.environ["MONGO_COLLECTION_DAILYREADINESS"] = config['collection_dailyreadiness']
    os.environ["MONGO_COLLECTION_DAILYPLAN"] = config['collection_dailyplan']
    os.environ["MONGO_COLLECTION_ATHLETESTATS"] = config['collection_athletestats']
    os.environ["MONGO_COLLECTION_COMPLETEDEXERCISES"] = config['collection_completedexercises']
    host = os.environ['MONGO_HOST']
    replicaset =os.environ['MONGO_REPLICASET']
    user = os.environ['MONGO_USER']
    password = os.environ['MONGO_PASSWORD']
    mongo_database = os.environ['MONGO_DATABASE']
    mongo_client = MongoClient(
        host,
        replicaset=replicaset if replicaset != '---' else None,
        ssl=True,
        serverSelectionTimeoutMS=10000,
    )
    database = mongo_client[mongo_database]
    database.authenticate(user, password, mechanism='SCRAM-SHA-1', source='admin')
    return database

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    try:
        if secret_name in ['postgres', 'secret_key_base']:
            service = 'users'
        else:
            service = 'plans'
        secret_name = '/'.join([service, os.environ['ENVIRONMENT'], secret_name])
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise ApplicationException('SecretsManagerError', json.dumps(e.response), 500)
    else:
        if 'SecretString' in get_secret_value_response:
            return json.loads(get_secret_value_response['SecretString'])
        else:
            return get_secret_value_response['SecretBinary']


def load_secrets():
    # Running in AWS Lambda, get secrets from Secrets Manager
    postgres_secret = get_secret("postgres")
    os.environ['POSTGRES_DB_URI'] = 'postgresql://{username}:{password}@{host}:{port}/{dbname}'.format(**postgres_secret)

    secret_key_base = get_secret("secret_key_base")
    os.environ['SECRET_KEY_BASE'] = secret_key_base['key']




#DATABASE = get_mongo_database()
