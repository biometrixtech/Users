from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError
from flask import Blueprint, request
import hashlib
import time
from boto3.dynamodb.conditions import Attr, Key
from models.device import Device
from collections import namedtuple
import boto3
import binascii
import json
import os
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound
import jwt

from decorators import authentication_required
from exceptions import InvalidSchemaException, NoSuchEntityException, UnauthorizedException, DuplicateEntityException, \
                       ApplicationException, InvalidPasswordFormatException
from flask_app import bcrypt

from db_connection import engine
from models import Users, Teams, TeamsUsers, TrainingGroups, TrainingGroupsUsers, Sport, SportHistory, Sport
from utils import *

push_notifications_table = boto3.resource('dynamodb').Table(os.environ['PUSHNOTIFICATIONS_DYNAMODB_TABLE_NAME'])
user_app = Blueprint('user', __name__)

session = Session(bind=engine)

sign_in_methods = ['json-subject-creation',
                   'json',
                   'json-accessory']

MAX_SESSIONS = 3

users_table = boto3.resource('dynamodb').Table('users-{ENVIRONMENT}-users'.format(**os.environ))


class DictionaryAttr(dict):
    def __init__(self, *args, **kwargs):
        super(DictionaryAttr, self).__init__(*args, **kwargs)
        self.__dict__ = self


def validate_password_format(password):
    # TODO: Add regular expression to match strong password
    if not len(password) > 6:
        raise InvalidPasswordFormatException('Password must be longer than 6 characters')
    return True


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


def date_exists(_date=None):
    if _date is None:
        return False
    else:
        return True


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
        "id": user.id,
        "personal_data": {
            "birth_date": format_date(user.birthday),
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number,
            "account_type": user.account_type,  # enum
            "account_status": user.account_status,
            "zip_code": user.zip_code
        },
        "role": user.role,
        "updated_date": format_datetime(user.updated_at),
        "training_status": user.status,
        "onboarding_status": user.onboarding_status,
        "sensor_pid": user.sensor_pid,
        "mobile_udid": user.mobile_udid,
        "system_type": user.system_type,
        "injury_status": user.injury_status,
        "agreed_terms_of_use": user.agreed_terms_of_use,
        "agreed_privacy_policy": user.agreed_privacy_policy,
        "cleared_to_play": user.cleared_to_play
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
    jwt_payload = {"sign_in_method": sign_in_method,
                   "created_at": datetime.datetime.now().isoformat(),
                   "role": role,
                   "exp": expires_at,
                   "user_id": str(user_id)
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
        "expires": expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    # TODO: Needs to connect to dynamodb, Figure out how to test locally when offline
    res = users_table.query(KeyConditionExpression=Key('id').eq(user_id))
    return res['Items'][0] if len(res['Items']) else None


def create_user_response_with_training_groups(session, user):
    user_resp = create_user_dictionary(user)

    teams = session.query(Teams).join(TeamsUsers).filter(TeamsUsers.user_id == user.id).all()
    training_groups = session.query(TrainingGroups).join(TrainingGroupsUsers) \
        .filter(TrainingGroupsUsers.user_id == user.id).all()

    user_resp['teams'] = [create_team_dictionary(team) for team in teams]
    user_resp['training_groups'] = [create_training_group_dictionary(training_group) for training_group in
                                    training_groups]
    return user_resp


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
        if password_received and user.password_digest:
            if bcrypt.check_password_hash(user.password_digest, password_received):  # Check if the password matches
                user_resp = create_user_response_with_training_groups(session, user)
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
        else:
            raise UnauthorizedException("Must supply a password.")
    raise NoSuchEntityException('User not found')


expected_user_keys = {
        "email": str,
        "password": str,
        "biometric_data": {
            "gender": str,
            "height": {"m": float},
            "mass": {"kg": float}
        },
        "personal_data": {
            "birth_date": str,
            "first_name": str,
            "last_name": str,
            "phone_number": str,
            "account_type": str,
            "account_status": str,
            "zip_code": str
        },
        "role": str,
        "system_type": str,
        "injury_status": str,
        "onboarding_status": list
        }

def add_missing_keys(dictionary, expected_format):
    for key, value in expected_format.items():
        try:
            if isinstance(dictionary[key], dict) or isinstance(value, dict):
                dictionary[key] = add_missing_keys(dictionary[key], value)
            elif not isinstance(value(dictionary[key]), value):
                raise InvalidSchemaException("{}:{} is of the wrong type.".format(key, dictionary[key]))
        except KeyError:
            dictionary[key] = None
    return dictionary


def create_user_object(user_data):
    """

    :param user_data: dictionary with user data
    :return: User ORM object ready to save
    """
    height_tuple = convert_to_ft_inches(user_data['biometric_data']['height'])
    if height_tuple:
        height_feet = height_tuple[0]
        height_inches = height_tuple[1]
    else:
        height_feet = None
        height_inches = None
    weight = convert_to_pounds(user_data['biometric_data']['mass'])
    password_hash = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
    # user_data = add_missing_keys(user_data, expected_user_keys)
    if not 'onboarding_status' in user_data.keys():
        user_data['onboarding_status'] = []

    if 'gender' in user_data['biometric_data'].keys():
        gender = user_data['biometric_data']['gender']
    elif 'sex' in user_data['biometric_data'].keys():
        gender = user_data['biometric_data']['sex']
    else:
        gender = None

    cleared_to_play = None
    agreed_terms_of_use = None
    agreed_privacy_policy = None
    if 'agreed_terms_of_use' in user_data:
        agreed_terms_of_use = user_data['agreed_terms_of_use']
    if 'agreed_privacy_policy' in user_data:
        agreed_privacy_policy = user_data['agreed_privacy_policy']
    if 'cleared_to_play' in user_data:
        cleared_to_play = user_data['cleared_to_play']

    try:
        user = Users(email=user_data['email'],
                    first_name=user_data['personal_data']['first_name'],
                    last_name=user_data['personal_data']['last_name'],
                    phone_number=user_data['personal_data']['phone_number'],
                    password_digest=password_hash,
                    created_at=datetime.datetime.now(),
                    updated_at=datetime.datetime.now(),
                    role=user_data['role'],
                    height_feet=height_feet,
                    height_inches=height_inches,
                    weight=weight,
                    gender=gender,
                    status=None,
                    birthday=user_data['personal_data']['birth_date'],
                    zip_code=user_data['personal_data']['zip_code'],
                    account_type=user_data['personal_data']['account_type'],
                    account_status = user_data['personal_data']['account_status'],
                    system_type = user_data['system_type'],
                    injury_status = user_data['injury_status'],
                    onboarding_status = user_data['onboarding_status'],
                    agreed_terms_of_use = agreed_terms_of_use,
                    agreed_privacy_policy = agreed_privacy_policy,
                    cleared_to_play = cleared_to_play
                     )
        return user
    except KeyError as e:
        raise ApplicationException(400, 'MissingRequiredUserFields', 'Missing parameters: {}'.format(str(e)))


def save_user_data(user, user_data):
    """
    Extracts the user_data from the dictionary and updates the orm. Essential the save as create_user_object
    :param user:
    :param user_data:
    :return:
    """
    if 'role' in user_data:
        user.role = user_data['role']
    if 'system_type' in user_data:
        user.system_type = user_data['system_type']
    if 'injury_status' in user_data:
        user.injury_status = user_data['injury_status']
    if 'onboarding_status' in user_data:
        user.onboarding_status = user_data['onboarding_status']

    if 'agreed_terms_of_use' in user_data:
        user.agreed_terms_of_use = user_data['agreed_terms_of_use']
    if 'agreed_privacy_policy' in user_data:
        user.agreed_privacy_policy = user_data['agreed_privacy_policy']
    if 'cleared_to_play' in user_data:
        user.cleared_to_play = user_data['cleared_to_play']

    if 'email' in user_data.keys():
        user.email = user_data['email']
    if 'personal_data' in user_data.keys():
        if 'first_name' in user_data['personal_data'].keys():
            user.first_name=user_data['personal_data']['first_name']
        if 'last_name' in user_data['personal_data'].keys():
            user.last_name=user_data['personal_data']['last_name']
        if 'phone_number' in user_data['personal_data'].keys():
            user.phone_number=user_data['personal_data']['phone_number']
        if 'birth_date' in user_data['personal_data'].keys():
            user.birthday = user_data['personal_data']['birth_date']
        if 'zip_code' in user_data['personal_data'].keys():
            user.zip_code = user_data['personal_data']['zip_code']
        if 'account_type' in user_data['personal_data'].keys():
            user.account_type = user_data['personal_data']['account_type']
        if 'account_status' in user_data['personal_data'].keys():
            user.account_status = user_data['personal_data']['account_status']

    if 'password' in user_data.keys():
        if validate_password_format(user_data['password']):
            user.password_digest = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')

    if 'biometric_data' in user_data.keys():
        if 'height' in user_data['biometric_data'].keys():
            height_tuple = convert_to_ft_inches(user_data['biometric_data']['height'])
            if height_tuple:
                height_feet = height_tuple[0]
                height_inches = height_tuple[1]
                user.height_feet = height_feet
                user.height_inches = height_inches
        if 'mass' in user_data['biometric_data'].keys():
            weight = convert_to_pounds(user_data['biometric_data']['mass'])
            user.weight=weight
        if 'gender' in user_data['biometric_data'].keys():
            user.gender=user_data['biometric_data']['gender']
        if 'sex' in user_data['biometric_data'].keys():
            user.gender=user_data['biometric_data']['sex']

    user.updated_at = datetime.datetime.now()

    return user


def validate_date(_date):
    """

    :param _date:
    :return:
    """
    return datetime.datetime.strptime(_date, '%m/%d/%Y')


def save_sports_history(user_data, user_id):
    """
    Create Sport and SportHistory ORM Objects and save data to database
    Expected dictionary format:
    {
        "sports": [{"name": "Lacrosse",
                    "positions": ["Goalie"],
                    "competition_level": "NCAA Division II",
                    "start_date": "1/1/2015",
                    "end_date": "3/1/2018",
                    "season_start_month": "January",
                    "season_end_month": "May"
                   },
                   ...
                  ]
    }
    :param user_data:
    :param user_id:
    :return:
    """
    if not user_id:
        raise InvalidSchemaException("save_sports_history: Missing User Profile")
    if 'sports' not in user_data.keys():
        raise InvalidSchemaException("save_sports_history: Missing Sports from data payload.")

    sports_info = user_data['sports']
    columns = ['name', 'positions', 'competition_level']
    sports_history = []
    for sport_info in sports_info:
        # valid_values = dict((col_name, validate_value(session, Sport, col_name, sport_info[col_name])) for col_name in columns)
        # TODO: What does validation look like for positions and DateTimes?

        name = validate_value(session, Sport, 'name', sport_info['name'])
        # positions = validate_positions(sport_info['positions'])
        competition_level = validate_value(session, Sport, 'competition_level', sport_info['competition_level'])
        start_date = validate_date(sport_info['start_date'])
        end_date = validate_date(sport_info['end_date'])
        for position in sport_info['positions']:
            position = validate_value(session, Sport, 'position', position)
            sport_history_obj = SportHistory(name=name,
                                             position=position,
                                             competition_level=competition_level,
                                             start_date=start_date,
                                             end_date=end_date
                                             # season_start_month
                                             # season_end
                                         )
            sports_history.append(sport_history_obj)
    return sports_history


def save_training_schedule(user_data, user_id):
    """
    Create the TrainingSchedule ORMs and save to the database
    :param user_data:
    :param user_id:
    :return:
    """
    pass


def validate_user_inputs(user_data):
    """
    Reviews each item in the payload to verify it is the correct type
    :param user_data:
    :return:
    """
    return user_data


@user_app.route('/', methods=['POST'])
#@xray_recorder.capture('routes.user.post')
def create_user():
    """
    Creates a new user given the data and validates the input parameters
    :param user_id:
    :return:
    """
    if not request.json:
        raise InvalidSchemaException("No data received. Verify headers include Content-Type: application/json")

    user_data = validate_user_inputs(request.json)
    try:
        existing_user = session.query(Users).filter(Users.email == user_data['email']).all()
    except Exception as e:
        raise ApplicationException(400, 'EmailLookupError', str(e))
    if existing_user:
        raise DuplicateEntityException("User Email {} already exists.".format(user_data['email']))

    try:
        user = create_user_object(user_data)
    except Exception as e:
        raise ApplicationException(400, 'InvalidSchema', str(e))
    if not user:
        raise ApplicationException(400, 'CreationError', 'Failed to create user')

    # save_training_groups(user_data, user.id)

    # save_sports_history(user_data, user.id)
    # save_training_schedule(user_data, user.id)

    # save_injuries(user_data, user.id)

    # If all objects persist save data to database
    session.add(user)
    session.commit()
    # Create User Session
    user_ddb = {'sessions': [], 'updated_date': '1970-01-01T00:00:00Z'}
    res = {'authorization': create_authorization_resp(user_id=user.id, sign_in_method='json', role=user.role)}
    res['authorization']['session_token'] = create_session_for_user(
        str(user.id),
        user_ddb['sessions'],
        user_ddb['updated_date'],
    )
    return res


@user_app.route('/<uuid:user_id>/authorize', methods=['POST'])
@xray_recorder.capture('routes.user.authorise')
def handle_user_authorise(user_id):
    if not request.json or 'session_token' not in request.json:
        raise InvalidSchemaException('Must supply session_token')

    user_ddb_res = get_user_from_ddb(user_id)
    if user_ddb_res is None:
        raise NoSuchEntityException()

    if 'sessions' not in user_ddb_res or request.json['session_token'] not in [s['id'] for s in user_ddb_res['sessions']]:
        raise UnauthorizedException('Session token is not valid for this user')

    return {'authorization': create_authorization_resp(user_id=user_ddb_res['id'], sign_in_method='json', role=None)}


@user_app.route('/<uuid:user_id>/logout', methods=['POST'])
@authentication_required
@xray_recorder.capture('routes.user.logout')
def handle_user_logout(user_id):
    user_ddb_res = get_user_from_ddb(user_id)
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    users_table.update_item(
        Key={'id': user_id},
        UpdateExpression='SET sessions = :sessions, updated_date = :updated_date',
        ExpressionAttributeValues={':sessions': [], ':updated_date': now},
    )

    if request.json['session_token'] not in [s['id'] for s in user_ddb_res['sessions']]:
        raise UnauthorizedException('Session token is not valid for this user')

    return {'authorization': create_authorization_resp(user_id=user_ddb_res['id'], sign_in_method='json', role=None)}


@user_app.route('/<uuid:user_id>', methods=['PUT'])
@authentication_required
def update_user(user_id):
    """
    Update the user information for any fields provided
    :param user_id:
    :return: 200 or 400 status code
    """
    if not validate_uuid4(user_id):
        raise InvalidSchemaException("user_id was not a valid UUID4")

    user_data = validate_user_inputs(request.json)
    try:
        user = session.query(Users).filter(Users.id == user_id).one()
    except Exception as e:
        raise ValueNotFoundInDatabase("user_id: {} not found.".format(user_id))

    if not user:
        raise NoSuchEntityException()


    user = save_user_data(user, user_data)
    try:
        session.commit()
        ret = {'user': create_user_dictionary(user)}
    finally:
        session.close()

    ret['message'] = 'Success!'
    return ret


@user_app.route('/<uuid:user_id>', methods=['DELETE'])
@authentication_required
def call_delete_user(user_id):
    """
    Wrapper around delete user to allow for delete_user to be tested without the request context required in the
      decorators of this function
    :param user_id:
    :return:
    """
    return delete_user(user_id, jwt_token=request.headers['jwt'])


def delete_user(user_id, jwt_token):
    """
    Verifies the user is authorized to delete this account
    :param user_id:
    :return:
    """
    if not verify_user_id_matches_jwt(jwt_token=jwt_token, user_id=user_id):
        raise UnauthorizedException('user_id supplied ({}) does not match user_id in jwt'.format(user_id))
    user = pull_user_object(user_id)
    user_id_found = user.id
    session.delete(user)
    session.commit()
    return {'message': 'Success. user_id={} was deleted'.format(user_id_found)}


@user_app.route('/<uuid:user_id>', methods=['GET'])
@authentication_required
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    """
        Wrapper around delete user to allow for get_user to be tested without the request context required in the
          decorators of this function
        :param user_id:
        :return:
    """
    return get_user(user_id)


def get_user(user_id):
    user = pull_user_object(user_id)
    user_resp = create_user_response_with_training_groups(session, user)
    return {'user': user_resp}


def verify_user_id_matches_jwt(jwt_token=None, user_id=None):
    """
    Extracts user_id from the jwt and compares it with the user_id supplied.
    :param jwt_token:
    :param user_id:
    :return: True/False
    """
    if not user_id or not jwt_token:
        raise ApplicationException(400, 'MissingData', 'Missing jwt or user_id')

    token = jwt.decode(jwt_token, os.getenv('SECRET_KEY_BASE'), algorithms='HS256', verify=False)
    if 'user_id' in token.keys():
        return token['user_id'] == str(user_id)
    raise ApplicationException(400, 'MissingUserIdFromJWT', 'user_id was not found in jwt token.')


@user_app.route('/<uuid:user_id>/sensor_mobile_pair', methods=['POST', 'GET', 'PUT', 'DELETE'])
@authentication_required
def sensor_mobile_pair_routing(user_id):
    """
    Handle each method for CRUD operations
    :param user_id:
    :return:
    """
    route_handlers = {'POST': create_sensor_mobile_pair,
                      'GET': retrieve_sensor_mobile_pair,
                      'PUT': create_sensor_mobile_pair,  # Since we're just updating the user object, create and update are the same
                      'DELETE': delete_sensor_mobile_pair
                      }
    if 'Authorization' not in request.headers:
        raise UnauthorizedException('Requires jwt token to validate user identity')
    if not verify_user_id_matches_jwt(jwt_token=request.headers['Authorization'], user_id=user_id):
        raise UnauthorizedException('user_id supplied ({}) does not match user_id in jwt'.format(user_id))

    # data = request.json
    # sensor_pid = data['sensor_pid']
    # mobile_udid = data['mobile_udid']
    if request.data:
        return route_handlers[request.method](user_id=user_id, **request.json)
    else:
        return route_handlers[request.method](user_id=user_id)


def pull_user_object(user_id):
    """
    Retrieves the user id and catches any errors.
    :param user_id:
    :return:
    """
    try:
        return session.query(Users).filter(Users.id == user_id).one()
    except NoResultFound as e:
        raise NoSuchEntityException('User {} was not found.'.format(user_id))
    # if not user:
    #     raise ApplicationException(400, 'UserNotFoundError', 'User {} not found.'.format(user_id))


def create_sensor_mobile_pair(user_id=None, sensor_pid=None, mobile_udid=None):
    """
    Adds the sensor and mobile info to a given user
    :param user_id:
    :return:
    """
    if user_id is None or sensor_pid is None or mobile_udid is None:
        raise InvalidSchemaException('Missing user_id, or sensor_pid, or mobile_udid')

    user = pull_user_object(user_id)

    user.sensor_pid = str(sensor_pid)
    user.mobile_udid = str(mobile_udid)

    session.commit()

    return {'message': 'Success!',
            'user_id': user.id,
            'sensor_pid': user.sensor_pid,
            'mobile_udid': user.mobile_udid
            }


def retrieve_sensor_mobile_pair(user_id=None):
    """
    Pull the sensor and mobile info to a given user
    :param user_id:
    :return:
    """
    if user_id is None:
        raise InvalidSchemaException('Missing user_id')

    user = pull_user_object(user_id)
    return {'message': 'Success!',
            'user_id': user.id,
            'sensor_pid': user.sensor_pid,
            'mobile_udid': user.mobile_udid
            }


def update_sensor_mobile_pair(user_id=None, sensor_pid=None, mobile_udid=None):
    """
    Adds the sensor and mobile info to a given user
    :param user_id:
    :return:
    """
    # Not Needed as it matches the create_sensor_mobile_pair function
    return create_sensor_mobile_pair(user_id=user_id, sensor_pid=sensor_pid, mobile_udid=mobile_udid)


def delete_sensor_mobile_pair(user_id=None):
    """
    Adds the sensor and mobile info to a given user
    :param user_id:
    :return:
    """
    if user_id is None:
        raise InvalidSchemaException('Missing user_id')

    user = pull_user_object(user_id)
    user.sensor_pid = None
    user.mobile_udid = None
    session.commit()
    return {'message': 'Sensor and mobile uid successfully deleted.',
            'user_id': user.id,
            'sensor_pid': user.sensor_pid,
            'mobile_udid': user.mobile_udid
            }


@user_app.route('/<uuid:user_id>/notify', methods=['POST'])
@authentication_required
@body_required({'message': str})
@xray_recorder.capture('routes.user.notify')
def handle_user_notify(user_id):
    devices = Device.get_many('owner_id', user_id)

    if len(devices) == 0:
        return {'message': f'No devices registered for user {user_id}'}, 540

    message = request.json['message']
    message_digest = hashlib.sha512(message.encode()).hexdigest()
    now_time = int(time.time())

    try:
        push_notifications_table.put_item(
            Item={
                'user_id': user_id,
                'message_hash': message_digest,
                'expiry_timestamp': now_time + 30,
            },
            ConditionExpression='attribute_not_exists(user_id) OR expiry_timestamp < :expiry_timestamp',
            ExpressionAttributeValues={':expiry_timestamp': now_time}
        )
    except ClientError as e:
        if 'ConditionalCheckFailedException' in str(e):
            return {'message': 'An identical message has already been sent to this user recently'}, 429
        raise e

    statuses = {}
    for device in devices:
        try:
            device.send_push_notification(message)
            statuses[device.id] = {'success': True, 'message': 'Success'}
        except ApplicationException as e:
            statuses[device.id] = {'success': False, 'message': str(e)}

    return statuses, 200
	
