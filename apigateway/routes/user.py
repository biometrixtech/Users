from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request, abort, jsonify

import boto3
import datetime
import json
import os
import uuid
from sqlalchemy.orm import Session
import jwt

from decorators import authentication_required
from exceptions import InvalidSchemaException, NoSuchEntityException, UnauthorizedException
from serialisable import json_serialise
from flask_app import bcrypt

import config
from db_connection import engine
from models import Users, Sensors, Teams, TeamsUsers


user_app = Blueprint('user', __name__)

session = Session(bind=engine)

sign_in_methods = ['json-subject-creation',
                   'json',
                   'json-accessory']


def extract_email_and_password_from_request(headers=None, params=None, data=None):
    """
    Check params, headers and json data for email and password
    :param request:
    :return:
    """

    try:
        email = data.get('email')
        password_received = data.get('password')
        if email and password_received:
            return email, password_received
        else:
            raise InvalidSchemaException('Email or password were missing')
    except KeyError as e:
        raise InvalidSchemaException('Email or password were missing')
    except TypeError as e:
        raise InvalidSchemaException('Request payload was not received')


def orm_to_dictionary(object_model, keys_to_exclude=None):
    """
    Converts a table object model into a dictionary for serialisation
    :param object_model:
    :return:
    """
    if keys_to_exclude:
        return {k: v for k, v in object_model.__dict__.items() if not k.startswith("_") and k not in keys_to_exclude}
    else:
        return {k: v for k, v in object_model.__dict__.items() if not k.startswith("_")}


def create_user_dictionary(user, team):
    """
    Convert the user ORM to the desired output format
    :param user_model:
    :return:
    """
    pass


def jwt_make_payload(user_id, sign_in_method, role):
    """
    Creates the payload for the jwt
    :return:
    """
    jwt_payload = {"user_id": str(user_id),
                   "created_at": datetime.datetime.now().isoformat(),
                   "sign_in_method": sign_in_method,
                   "role": role
                   }
    hmac_secret = config.SECRET_KEY_BASE
    jwt_payload_encoded = jwt.encode(jwt_payload, hmac_secret, algorithm='HS256') #, default=json_serialise)
    return jwt_payload_encoded


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
        # abort(401)
        return jsonify({
                        "message": "No data received. Verify headers include Content-Type: application/json",
                        "received": request.data}
                       )

    email, password_received = extract_email_and_password_from_request(data=request.json)

    # Attempt to authenticate the user
    user_query = session.query(Users).filter_by(email=email)
    user = user_query.first()
    if user:
        # recent_sensors = session.query(Sensors).filter(Sensors.last_user_id == user.id).order_by(Sensors.updated_at).limit(3).all()
        teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
        if password_received:
            if bcrypt.check_password_hash(user.password_digest, password_received): # Check if the password matches
                keys_to_exclude = ['avatar_file_name',
                                   'avatar_file_size',
                                   'avatar_updated_at',
                                   'avatar_content_type',
                                   'password_digest']
                user_resp = orm_to_dictionary(user, keys_to_exclude)
                user_resp['needs_base_calibration'] = False # Legacy option as devices no longer need to be calibrated
                user_resp['jwt'] = jwt_make_payload(user_id=user_resp['id'],
                                                    sign_in_method='json',
                                                    role=user_resp['role']
                                                   )
                user_resp['recent_sensors'] = [orm_to_dictionary(sensor) for sensor in recent_sensors]
                user_resp['teams'] = [orm_to_dictionary(team) for team in teams]
                return json.dumps(user_resp, default=json_serialise)
            else:
                raise UnauthorizedException("Password was not correct.")
    return json.dumps({'message': 'User not found'}, default=json_serialise)


@user_app.route('/<user_id>', methods=['GET'])
@authentication_required
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    if not validate_uuid4(user_id):
        raise InvalidSchemaException('user_id must be a uuid')

    user_data, teams, training_groups = query_postgres([
        (
            """SELECT
                    id AS user_id,
                    role AS user_role,
                    organization_id AS organization_id,
                    created_at AS created_date,
                    updated_at AS updated_date,
                    weight AS user_mass_lb
                FROM users WHERE id = %s""",
            [user_id]
        ),
        (
            """SELECT team_id FROM teams_users WHERE user_id = %s""",
            [user_id]
        ),
        (
            """SELECT training_group_id FROM training_groups_users WHERE user_id = %s""",
            [user_id]
        ),
    ])
    print(user_data, teams, training_groups)
    if len(user_data) == 0:
        raise NoSuchEntityException()

    if user_data[0]['user_mass_lb']:
        user_mass = float(user_data[0]['user_mass_lb'])
    else:
        user_mass = 0

    user = {
        'user_id': user_data[0]['user_id'],
        'role': user_data[0]['user_role'],
        'created_date': datetime.datetime.strptime(user_data[0]['created_date'], "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ"),
        'updated_date': datetime.datetime.strptime(user_data[0]['updated_date'], "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ"),
        'team_id': teams[0]['team_id'] if len(teams) else None,
        'training_group_ids': [t['training_group_id'] for t in training_groups],
        'mass': {
            'lb': round(user_mass, 1),
            'kg': round(user_mass * 0.453592, 1),
        }
    }

    return json.dumps({'user': user}, default=json_serialise)


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
