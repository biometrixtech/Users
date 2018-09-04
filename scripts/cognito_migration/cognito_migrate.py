import os
import requests
import json
import boto3
import argparse
from collections import namedtuple
from sqlalchemy.orm import Session
from utils import feet_to_meters, lb_to_kg, format_date, format_datetime
from boto3.dynamodb.conditions import Attr, Key
from exceptions import ApplicationException
from botocore.exceptions import ClientError

def get_users_from_postgres():
    """get user information from postgres"""
    user_query = session.query(UsersPostgres)
    users = user_query.all()

    return users

def create_user(user_data):
    """ create new user in cognito and transfer data to conginto and ddb"""
    url = "https://apis.{env}.fathomai.com/users/user".format(env=os.environ['ENVIRONMENT'])
    header = {"Content-Type": "application/json",
              "User-Agent": "biometrix/cognitomigrator"
              }
    body = user_data

    r = requests.post(url, data=json.dumps(body), headers=header)
    if r.status_code == 409:
        url = "https://apis.{env}.fathomai.com/users/1_0/user/login".format(env=os.environ['ENVIRONMENT'])
        body = {"personal_data": {"email": user_data["personal_data"]["email"]},
                "password": "Fathom123!"}
        res = requests.post(url, data=json.dumps(body), headers=header)
        if res.status_code == 200:
            print("user already exists")
            user_id = res.json()["user"]["id"]
            return user_id
    elif r.status_code == 201:  
        response = r.json()
        user_id = response["user"]["id"]
        return user_id
    else:
        raise ValueError

def migrate_sessions_to_ddb(legacy_user_id, user_id):
    """copy all session data from postgres to dynamodb"""
    sessions_query = session.query(SessionPostgres).filter_by(user_id=legacy_user_id)
    session_events = sessions_query.all()
    for session_event in session_events:
        session_ddb = SessionDDB(session_id=str(session_event.id),
                                 event_date=format_datetime(session_event.happened_at),
                                 created_date=format_datetime(session_event.created_at),
                                 updated_date=format_datetime(session_event.updated_at),
                                 user_id=user_id,
                                 training_group_ids=[str(s) for s in session_event.training_group_ids] ,
                                 session_status='PROCESSING_COMPLETE',
                                 s3_files=str(session_event.sensor_data_filename)
                                 ).json_serialise()
        ddb_resource = boto3.resource('dynamodb')
        ddb_table = ddb_resource.Table('preprocessing-dev-ingest-sessions-migrationtest')
        cx = Attr('id').not_exists() | Attr('id').exists() if False else Attr('id').not_exists()
        try:
            ddb_table.put_item(
                                Item=session_ddb,
                                ReturnConsumedCapacity='INDEXES',
                                ReturnItemCollectionMetrics='SIZE',
                                ConditionExpression=cx,
                            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                print('Session: {} already exists in DynamoDB'.format(session_event.id))
            else:
                raise e


def update_sessions_in_ddb(legacy_user_id, user_id):
    legacy_user_id = str(legacy_user_id)
    ddb_resource = boto3.resource('dynamodb')
    ddb_table = ddb_resource.Table('preprocessing-{env}-ingest-sessions-migrationtest'.format(env=os.environ['ENVIRONMENT']))
    ret = ddb_table.query(**{k: v for k, v in {
                'IndexName': 'user_id-event_date',
                'Select': 'ALL_ATTRIBUTES',
                'Limit': 10000,
                'ConsistentRead': False,
                'ReturnConsumedCapacity': 'INDEXES',
                'KeyConditionExpression': Key('user_id').eq(legacy_user_id),
                'FilterExpression': None,
                'ExclusiveStartKey': None,
            }.items() if v is not None})
    for item in ret['Items']:
        key = {}
        key['id'] = item['id']
        ddb_table.update_item(
                    Key=key,
                    UpdateExpression='set user_id = :val1',
                    ExpressionAttributeValues={
                            ':val1': user_id
                    }
                )


def update_mongo(legacy_user_id, user_id):
    """update user_id in all relevant mongo collections to the new id
        collections to update:
            ---v3 data---
            athleteStats: athlete_id
            completedExercises: athlete_id
            dailyPlan: user_id
            dailyReadiness: user_id
            ---v2 data---
            activeBlockStats: userId
            dateStats: userId
            progCompDateStats: userId
            progCompStats: userId
            sessionStats: userId
            twoMinuteStats: userId
    """
    # Sample code for mongo update
    query = {"user_id": legacy_user_id}
    mongo_collection = get_mongo_collection('dailyplan')
    mongo_collection.update_many(query, {'$set': {'user_id': user_id}})
    mongo_collection = get_mongo_collection('dailyreadiness')
    mongo_collection.update_many(query, {'$set': {'user_id': user_id}})

    query = {"athlete_id": legacy_user_id}
    mongo_collection = get_mongo_collection('athletestats')
    mongo_collection.update_many(query, {'$set': {'athlete_id': user_id}})
    mongo_collection = get_mongo_collection('completedexercises')
    mongo_collection.update_many(query, {'$set': {'athlete_id': user_id}})


    query = {"userId": str(legacy_user_id)}
    mongo_collection = get_mongo_collection('activeBlockStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    mongo_collection = get_mongo_collection('dateStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    mongo_collection = get_mongo_collection('progCompDateStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    mongo_collection = get_mongo_collection('progCompStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    mongo_collection = get_mongo_collection('sessionStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    mongo_collection = get_mongo_collection('twoMinuteStats')
    mongo_collection.update_many(query, {'$set': {'userId': user_id}})
    print("Successfully updated mongo collections for user: {}".format(legacy_user_id))


def create_user_dictionary(user):
    """
    Convert the user ORM to the desired output format
    :param user:
    :return:
    """
    if isinstance(user, dict):
        user = namedtuple("User", user.keys())(*user.values())

    return {
            "password": 'Fathom12!',
            
        "biometric_data": {
            "sex": str(user.gender),
            "height": {
                "ft_in": [user.height_feet, user.height_inches or 0],
                "m": feet_to_meters(user.height_feet, user.height_inches)
            },
            "mass": {
                "lb": user.weight,
                "kg": lb_to_kg(user.weight)
            }
        },
        "created_date": format_datetime(user.created_at),
        "deleted_date": format_datetime(user.deleted_at),
        "id": str(user.id),
        "personal_data": {
            "email": user.email,
            "birth_date": format_date(user.birthday),
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": "+1"+user.phone_number,
            "account_type": user.account_type if user.account_type is not None else 'free',  # enum
            "account_status": user.account_status if user.account_status is not None else 'active',
            "zip_code": user.zip_code
        },
        "role": user.role,
        "updated_date": format_datetime(user.updated_at),
        "training_status": user.status,
        "onboarding_status": user.onboarding_status,
        "sensor_pid": user.sensor_pid,
        "mobile_udid": user.mobile_udid,
        "system_type": user.system_type if user.system_type is not None else "1-sensor",
        "injury_status": user.injury_status if user.injury_status is not None else 'healthy',
        "agreed_terms_of_use": user.agreed_terms_of_use if user.agreed_terms_of_use is not None else True,
        "agreed_privacy_policy": user.agreed_privacy_policy if user.agreed_privacy_policy is not None else True,
        "cleared_to_play": user.cleared_to_play
    }


def main():
    # get all existing users from postgres
    users = get_users_from_postgres()
    users_count = len(users)
    print("Starting migration for {} users".format(users_count))
    count = 0
    for user in users:
#        if str(user.id) == '303bfa91-8e3a-4c1b-be8f-26ec3734ed74': #only doing this for a single test user
#        if str(user.id) == 'a1233423-73d3-4761-ac92-89cc15921d34':
        legacy_user_id = user.id
        user_dict = create_user_dictionary(user)

        user_email = user_dict['personal_data']['email']
        print("Creating a new user in Cognito and DynamoDB for: {}".format(user_email))
        user_id = create_user(user_dict)
        print(user_id)

        print("Updating existing sessions in ddb to new user")
        update_sessions_in_ddb(legacy_user_id, user_id)
        print("Migrating Sessions from postgres to DynamoDB for user: {}".format(user_email))
        migrate_sessions_to_ddb(legacy_user_id, user_id)
        print("Updating documents in mongoDB for user: {}".format(user_email))
        update_mongo(legacy_user_id, user_id)
        count += 1
        print("Successfully migrated {}/{} users".format(count, users_count))


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Deploy a new version of a service to an environment')
    parser.add_argument('--region',
                        choices=['us-west-2'],
                        default='us-west-2',
                        help='AWS Region')
    parser.add_argument('environment',
                        choices=['dev', 'test', 'production'],
                        help='Environment')

    args = parser.parse_args()

    os.environ['ENVIRONMENT'] = args.environment
    from config import load_secrets, get_mongo_collection
    load_secrets()
    from db_connection import engine
    session = Session(bind=engine)
    from models.users import UsersPostgres
    from models.sessions import SessionPostgres, SessionDDB

    try:
        main()
    except KeyboardInterrupt:
        print('Exiting')
        exit(1)
    except ApplicationException as ex:
        print(str(ex))
        exit(1)
    except Exception as ex:
        print(str(ex))
        raise ex
    else:
        exit(0)

#
