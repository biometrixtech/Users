from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request, abort, jsonify

import boto3
import datetime
import json
import os
import uuid
from sqlalchemy.orm import Session
import jwt


from exceptions import InvalidSchemaException, NoSuchEntityException
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
        email = data['email']
        password_received = data['password']
        return email, password_received
    except Exception as e:
        print(e)
        abort(404)


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


def create_avatar_url(avatar_file_name):
    """
    Converts the file_name into a valid url
    :param avatar_file_name:
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
        "auth_token": "",
        "id": "",
        "email": "glitch0@gmail.com",
        "role": "biometrix_admin",
        "first_name": "Chris",
        "last_name": "Cassano",
        "facebook_id": null,
        "phone_number": "9191234567",
        "created_at": "2017-04-14T23:49:52.777Z",
        "updated_at": "2018-04-02T17:16:40.280Z",
        "position": "Administrator",
        "active": true,
        "in_training": false,
        "deleted_at": null,
        "height_feet": 6,
        "height_inches": null,
        "weight": 120,
        "gender": "male",
        "status": "full_volume",
        "push_token": null,
        "push_type": null,
        "onboarded": true,
        "birthday": "01/02/03",
        "organization_id": "f62fbd5b-aafc-436f-b358-be2b34e1fe58",
        "primary_training_group_id": null,
        "year_in_school": 2,
        "avatar_url": "https://dashboard-v2.biometrixtech.com/images/full/missing.png",
        "recent_sensors": [],
        "needs_base_calibration": false,
        "jwt": "...",
        "teams": [
            {
                "id": "f87e1deb-f022-4223-acaa-4926b6094343",
                "name": "Womens Soccer",
                "organization_id": "f62fbd5b-aafc-436f-b358-be2b34e1fe58",
                "created_at": "2017-08-15T07:55:39.894Z",
                "updated_at": "2017-10-16T16:11:34.424Z",
                "athlete_subscriptions": 10,
                "athlete_manager_subscriptions": 10,
                "gender": "female",
                "sport_id": "8534c4ea-4b37-40a0-a037-cad00cf03f74"
            }
        ]
        }
    """
    # Check for email and password within the request
    email, password_received = extract_email_and_password_from_request(data=request.json)

    # Attempt to authenticate the user
    user_query = session.query(Users).filter_by(email=email)
    user = user_query.first()
    recent_sensors = session.query(Sensors).filter(Sensors.last_user_id == user.id).order_by(Sensors.updated_at).limit(3).all()
    teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
    if user and password_received:
        if bcrypt.check_password_hash(user.password_digest, password_received): # Check if the password matches
            keys_to_exclude = ['avatar_file_name',
                               'avatar_file_size',
                               'avatar_updated_at',
                               'avatar_content_type',
                               'password_digest']
            user_resp = orm_to_dictionary(user, keys_to_exclude)
            user_resp['needs_base_calibration'] = False # Legacy option as devices no longer need to be calibrated
            user_resp['avatar_url'] = create_avatar_url(user.avatar_file_name)
            user_resp['jwt'] = jwt_make_payload(user_id=user_resp['id'],
                                                sign_in_method='json',
                                                role=user_resp['role']
                                               )
            user_resp['recent_sensors'] = [orm_to_dictionary(sensor) for sensor in recent_sensors]
            user_resp['teams'] = [orm_to_dictionary(team) for team in teams]
            return json.dumps(user_resp, default=json_serialise)
    return json.dumps({'message': 'User not found'}, default=json_serialise)


@user_app.route('/<user_id>', methods=['GET'])
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

    user_mass = float(user_data[0]['user_mass_lb'])

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
