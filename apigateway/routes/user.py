from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
from collections import namedtuple
import boto3
import datetime
import json
import os
import uuid
from sqlalchemy.orm import Session
import jwt

from decorators import authentication_required
from exceptions import InvalidSchemaException, NoSuchEntityException, UnauthorizedException, DuplicateEntityException
from flask_app import bcrypt

from db_connection import engine
from models import Users, Teams, TeamsUsers, TrainingGroups, TrainingGroupsUsers
from utils import *

user_app = Blueprint('user', __name__)

session = Session(bind=engine)

sign_in_methods = ['json-subject-creation',
                   'json',
                   'json-accessory']


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
                return {
                    "authorization": create_authorization_resp(user_id=user_resp['id'], sign_in_method='json', role=user_resp['role']),
                    "user": user_resp
                }
            else:
                raise UnauthorizedException("Password was not correct.")
    raise NoSuchEntityException('User not found')


def create_user_object(user_data):
    """
    
    :param user_data: dictionary with user data 
    :return: User ORM object ready to save
    """
    height_feet, height_inches = convert_to_ft_inches(user_data['biometric_data']['height'])
    weight = convert_to_pounds(user_data['biometric_data']['mass'])
    password_hash = bcrypt.generate_password_hash(user_data['password'])
    user = Users(email=user_data['email'],
                first_name=user_data['personal_data']['first_name'],
                last_name=user_data['personal_data']['last_name'],
                phone_number=user_data['personal_data']['phone_number'],
                password_digest=password_hash,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now(),
                # avatar_file_name
                # avatar_content_type
                # avatar_file_size
                # avatar_updated_at
                # position
                role=user_data['role'],
                # active
                # in_training
                height_feet=height_feet,
                height_inches=height_inches,
                weight=weight,
                gender=user_data['biometric_data']['gender'],
                status=None,
                # onboarded
                birthday=user_data['personal_data']['birth_date']
               )
    return user


@user_app.route('/', methods=['POST'])
@xray_recorder.capture('routes.user.get')
def create_user():
    """
    Creates a new user given the data and validates the input parameters
    :param user_id:
    :return:
    """
    if not request.json:
        raise InvalidSchemaException("No data received. Verify headers include Content-Type: application/json")
    user_data = validate_inputs(request.json)

    user = create_user_object(user_data)

    
    # training_groups = TrainingGroups()
    # sports = Sports()
    # injuries = Injuries()
    # training_schedule = TrainingSchedule()
    # training_strength_conditioning = StrengthConditioning()


@user_app.route('/<user_id>', methods=['GET'])
@authentication_required
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    if not validate_uuid4(user_id):
        raise InvalidSchemaException('user_id must be a uuid')

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


def validate_uuid4(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False
