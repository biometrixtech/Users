from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
from boto3.dynamodb.conditions import Attr, Key
from collections import namedtuple
import boto3
import binascii
import datetime
import json
import os
import uuid
from sqlalchemy.orm import Session
import jwt

from decorators import authentication_required
from exceptions import InvalidSchemaException, NoSuchEntityException, UnauthorizedException
from flask_app import bcrypt

from db_connection import engine
from models import Users, Teams, TeamsUsers, TrainingGroups, TrainingGroupsUsers


user_app = Blueprint('user', __name__)

session = Session(bind=engine)

sign_in_methods = ['json-subject-creation',
                   'json',
                   'json-accessory']

MAX_SESSIONS = 3

users_table = boto3.resource('dynamodb').Table('users-{ENVIRONMENT}-users'.format(**os.environ))


def extract_email_and_password_from_request(data):
    """
    Check params, headers and json data for email and password
    :param data:
    :return:
    """

    try:
        email = data.get('email')
        password_received = data.get('password')
        if email and password_received:
            return email, password_received
        else:
            raise InvalidSchemaException('Email or password were missing')
    except KeyError:
        raise InvalidSchemaException('Email or password were missing')
    except TypeError:
        raise InvalidSchemaException('Request payload was not received')


def feet_to_meters(feet, inches):
    """
    Converts feet + inches into meters
    :param feet:
    :param inches:
    :return:
    """
    if feet:
        if inches:
            return (feet + inches/12)*0.3048
        else:
            return feet*0.3048
    elif inches:
        return (inches/12)*0.3048


def lb_to_kg(weight_lbs):
    """
    Converts pounds to kilograms.
    Handles the case where the weight is None
    :param weight_lbs:
    :return:
    """
    if weight_lbs:
        return weight_lbs * 0.453592


def format_datetime(date_input):
    """
    Formats a date in ISO8601 short format.
    Handles the case where the input is None
    :param date_input:
    :return:
    """
    if date_input is None:
        return None
    if not isinstance(date_input, datetime.datetime):
        date_input = datetime.datetime.strptime(date_input, "%Y-%m-%dT%H:%M:%S.%f")
    return date_input.strftime("%Y-%m-%dT%H:%M:%SZ")


def format_date(date_input):
    """
    Formats a date in ISO8601 short format.
    Handles the case where the input is None
    :param date_input:
    :return:
    """
    if date_input is None:
        return None
    if isinstance(date_input, datetime.datetime):
        return date_input.strftime("%Y-%m-%d")
    else:
        for format_string in ('%Y-%m-%d', '%m/%d/%y', '%Y-%m'):
            try:
                date_input = datetime.datetime.strptime(date_input, format_string)
                return date_input.strftime("%Y-%m-%d")
            except ValueError:
                pass
        return None
        # raise ValueError('no valid date format found')


def create_user_dictionary(user):
    """
    Convert the user ORM to the desired output format
    :param user:
    :return:
    """
    if isinstance(user, dict):
        user = namedtuple("User", user.keys())(*user.values())

    return {
        "biometric_data": {
            "sex": user.gender,
            "height": {
                "ft_in": [user.height_feet, user.height_inches or 0],
                "m": round(feet_to_meters(user.height_feet, user.height_inches), 2)
            },
            "mass": {
                "lb": round(user.weight, 1),
                "kg": round(lb_to_kg(user.weight), 1)
            }
        },
        "created_date": format_datetime(user.created_at),
        "deleted_date": format_datetime(user.deleted_at),
        "id": user.id,
        "personal_data": {
            "birth_date": format_date(user.birthday),
            "email": user.email,
            # "zip_code": user.zipcode,  # TODO: Add to database
            # "competition_level": enum,
            # "sports": [sports_position_id,
            #     sports_position_id,
            #     sports_position_id
            # ],
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number,
            # "account_type": user.account_type,   # enum
            "account_status": user.active,
        },
        "role": user.role,
        "updated_date": format_datetime(user.updated_at),
        "training_status": user.status,
    }


def create_team_dictionary(team):
    """
    Format a Team object in accordance with the schema
    :param team:
    :return: dict
        {
            "id": Uuid,
            "name": string,
            "organization_id": Uuid,
            "created_date": Datetime,
            "updated_date": Datetime,
            "athlete_subscriptions": integer,
            "athlete_manager_subscriptions": integer,
            "gender": Gender,
            "sport_id": Uuid
        }
    """
    if isinstance(team, dict):
        team = namedtuple("Team", team.keys())(*team.values())
    return {
        "athlete_manager_subscriptions": team.athlete_manager_subscriptions,
        "athlete_subscriptions": team.athlete_subscriptions,
        "created_date": format_datetime(team.created_at),
        "gender": team.gender,
        "id": team.id,
        "name": team.name,
        "organization_id": team.organization_id,
        "sport_id": team.sport_id,
        "updated_date": format_datetime(team.updated_at),
    }


def create_training_group_dictionary(training_group):
    if isinstance(training_group, dict):
        training_group = namedtuple("TrainingGroup", training_group.keys())(*training_group.values())
    return {'id': training_group.id}


def jwt_make_payload(expires_at=None, user_id=None, sign_in_method=None, role=None):
    """
    Creates the payload for the jwt
    :return:
    """
    jwt_payload = {"user_id": str(user_id),
                   "created_at": datetime.datetime.now().isoformat(),
                   "sign_in_method": sign_in_method,
                   "role": role,
                   "exp": expires_at
                   }
    jwt_payload_encoded = jwt.encode(jwt_payload, os.environ['SECRET_KEY_BASE'], algorithm='HS256')
    return jwt_payload_encoded


def create_authorization_resp(**kwargs):
    """
    Return a dictionary for the authorization data
    :param kwargs:
    :return:
    """
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
    token = jwt_make_payload(expires_at=expiration_time, **kwargs)
    return {
        "expires": expiration_time.isoformat(),
        "jwt": token
    }


def create_session_for_user(user_id, sessions, atomic_date):
    """
    Expire old sessions for the user, and create a new session token
    :param user_id: String uuid
    :param atomic_date: String ISO8601 datetime
    :param sessions: List of objects
    :return: string new session token
    """
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Remove old sessions to get down below the limit
    sessions.sort(key=lambda s: s['created_date'])
    sessions = sessions[min(1-MAX_SESSIONS, 0):]

    new_session_id = binascii.hexlify(os.urandom(32)).decode()
    sessions.append({
        'created_date': now,
        'id': new_session_id,
    })
    users_table.update_item(
        Key={'id': user_id},
        UpdateExpression='SET sessions = :sessions, updated_date = :updated_date',
        ExpressionAttributeValues={':sessions': sessions, ':updated_date': now},
        ConditionExpression=Attr('updated_date').eq(atomic_date) | Attr('updated_date').not_exists(),
    )
    return new_session_id


def get_user_from_ddb(user_id):
    res = users_table.query(KeyConditionExpression=Key('id').eq(user_id))
    return res['Items'][0] if len(res['Items']) else None


@user_app.route('/sign_in', methods=['POST'])
def user_sign_in():
    """
    Given a username and password, this retrieves the user object and authenticates the user, returning their info if valid.
    :return: {
            "biometric_data": {
                "gender": Gender,
                "height": {
                    "ft_in": [integer, integer],
                    "m": number
                },
                "mass": {
                    "lb": number,
                    "kg": number
                }
            },
            "created_date": Datetime,
            "deleted_date": Datetime,
            "id": Uuid,
            "organization_id": Uuid,
            "personal_data": {
                "birth_date": Date,
                "email": string,
                "zip_code": number,
                "competition_level": enum,
                "sports": [sports_position_id,
                    sports_position_id,
                    sports_position_id
                ],
                "first_name": string,
                "last_name": string,
                "phone_number": Phonenumber,
                "account_type": enum,
                "account_status" enum,
            },
            "role": enum,
            "updated_date": Datetime,
            "training_status": enum,
            "teams": [Team, ...],
            "training_groups": [TrainingGroup, ...]
        }
    """
    # Check for email and password within the request
    if not request.json:
        raise InvalidSchemaException("No data received. Verify headers include Content-Type: application/json")

    email, password_received = extract_email_and_password_from_request(request.json)

    # Attempt to authenticate the user
    user_query = session.query(Users).filter_by(email=email)
    user = user_query.first()
    if user:
        teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
        training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers)\
                                 .filter(TrainingGroupsUsers.user_id == user.id).all()
        if password_received:
            if bcrypt.check_password_hash(user.password_digest, password_received):  # Check if the password matches
                user_resp = create_user_dictionary(user)
                user_resp['teams'] = [create_team_dictionary(team) for team in teams]
                user_resp['training_groups'] = [create_training_group_dictionary(training_group) for training_group in training_groups]

                user_ddb_res = get_user_from_ddb(str(user_resp['id'])) or {'sessions': [], 'updated_date': '1970-01-01T00:00:00Z'}
                ret = {
                    "authorization": create_authorization_resp(user_id=user_resp['id'], sign_in_method='json', role=user_resp['role']),
                    "user": user_resp
                }
                ret['authorization']['session_token'] = create_session_for_user(
                    str(user_resp['id']),
                    user_ddb_res['sessions'],
                    user_ddb_res['updated_date'],
                )
                return ret
            else:
                raise UnauthorizedException("Password was not correct.")
    raise NoSuchEntityException('User not found')


@user_app.route('/<uuid:user_id>', methods=['GET'])
@authentication_required
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    user_data, teams, training_groups = query_postgres([
        (
            """SELECT * FROM users WHERE id = %s""",
            [user_id]
        ),
        (
            """SELECT * FROM teams 
                    LEFT JOIN teams_users ON teams.id=teams_users.team_id 
                    WHERE teams_users.user_id = %s""",
            [user_id]
        ),
        (
            """SELECT * FROM training_groups 
                    LEFT JOIN training_groups_users ON training_groups.id=training_groups_users.training_group_id
                     WHERE training_groups_users.user_id = %s""",
            [user_id]
        ),
    ])
    print(user_data, teams, training_groups)
    if len(user_data) == 0:
        raise NoSuchEntityException()

    if user_data[0]['weight']:
        user_mass = float(user_data[0]['weight'])
    else:
        user_mass = 0

    user_resp = create_user_dictionary(user_data[0])
    user_resp['teams'] = [create_team_dictionary(team) for team in teams]
    user_resp['training_groups'] = [create_training_group_dictionary(training_group) for training_group in training_groups]

    return {'user': user_resp}


@xray_recorder.capture('apigateway.query_postgres')
def query_postgres(queries):
    lambda_client = boto3.client('lambda', region_name=os.environ['AWS_REGION'])
    res = json.loads(lambda_client.invoke(
        FunctionName='arn:aws:lambda:{AWS_REGION}:{AWS_ACCOUNT_ID}:function:infrastructure-{ENVIRONMENT}-querypostgres'.format(**os.environ),
        Payload=json.dumps({
            "Queries": [{"Query": query[0], "Parameters": query[1]} for query in queries],
            "Config": {"ENVIRONMENT": os.environ['ENVIRONMENT']}
        }),
    )['Payload'].read().decode('utf-8'))
    if len(list(filter(None, res['Errors']))):
        raise Exception(list(filter(None, res['Errors'])))
    else:
        return res['Results']
