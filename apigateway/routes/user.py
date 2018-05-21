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

from db_connection import engine
from models import Users, Teams, TeamsUsers, TrainingGroups, TrainingGroupsUsers


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


def create_user_dictionary(user):
    """
    Convert the user ORM to the desired output format
    :param user_model:
    :return:
    """
    return {"biometric_data": {
                "sex": user.gender,
                "height": {
                    "ft_in": [user.height_feet, user.height_inches],
                    "m": feet_to_meters(user.height_feet, user.height_inches)
                },
                "mass": {
                    "lb": round(user.weight, 1),
                    "kg": round(lb_to_kg(user.weight), 1)
                }
            },
            "created_date": user.created_at,
            "deleted_date": user.deleted_at,
            "id": user.id,
            "personal_data": {
                "birth_date": user.birthday,
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
                #"account_type": user.account_type,   # enum
                "account_status": user.active,
            },
            "role": user.role,
            "updated_date": user.updated_at,
            "training_status": user.status,
            #"teams": [Team, ...],
            #"training_groups": [TrainingGroup, ...]
        }


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
    return  {
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
        training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers)\
                                 .filter(TrainingGroupsUsers.user_id == user.id).all()
        if password_received:
            if bcrypt.check_password_hash(user.password_digest, password_received): # Check if the password matches
                user_resp = create_user_dictionary(user)
                user_resp['teams'] = [orm_to_dictionary(team) for team in teams]
                user_resp['training_groups'] = [orm_to_dictionary(training_group) for training_group in training_groups]
                resp = {"authorization": create_authorization_resp(
                                                user_id=user_resp['id'],
                                                sign_in_method='json',
                                                role=user_resp['role']
                                                ),
                        "user": user_resp
                        }
                return json.dumps(resp, default=json_serialise)
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
