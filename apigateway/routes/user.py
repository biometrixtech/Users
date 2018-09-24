from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError
from flask import Blueprint, request
import boto3
import hashlib
import time
import os
import json
import requests

from decorators import authentication_required, body_required, self_authentication_required
from exceptions import DuplicateEntityException, UnauthorizedException, NoSuchEntityException, ForbiddenException, ApplicationException
from utils import ftin_to_metres, lb_to_kg
from models.user import User
from models.user_data import UserData
from models.device import Device
from query_postgres import query_postgres
from utils import nowdate

push_notifications_table = boto3.resource('dynamodb').Table(os.environ['PUSHNOTIFICATIONS_DYNAMODB_TABLE_NAME'])
user_app = Blueprint('user', __name__)


@user_app.route('/login', methods=['POST'])  # TODO was /sign_in
@body_required({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.login')
def user_login():
    user = User(request.json['personal_data']['email'])
    user_record = user.get()

    try:
        authorisation = user.login(password=request.json['password'])
    except UnauthorizedException as e:
        if user_record['migrated_date'] is not None:
            # Try migrating them
            try:
                authorisation = _attempt_cognito_migration(
                    user,
                    request.json['personal_data']['email'],
                    request.json['password']
                )
            except Exception:
                # Raise the original error
                raise e
        else:
            raise e

    return {
        'user': user_record,
        'authorization': authorisation
    }


@user_app.route('/', methods=['POST'])
@body_required({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.post')
def create_user():
    """
    Creates a new user
    """
    if 'role' in request.json and request.json['role'] != 'athlete':
        raise ForbiddenException('Cannot create user with elevated role')
    request.json['role'] = 'athlete'

    if 'User-Agent' in request.headers and request.headers['User-Agent'] == 'biometrix/cognitomigrator':
        request.json['migrated_date'] = nowdate()
    elif 'migrated_date' in request.json:
        del request.json['migrated_date']

    # Get the metric values for height and mass if only imperial values were given
    metricise_values()

    user = User(request.json['personal_data']['email'])

    res = {'user': {}}

    # This pair of operations needs to be atomic, we don't want to have the user saved in Cognito (hence their email
    # address is 'squatted' and can't be re-registered) but their data not saved in DDB
    try:
        # Create Cognito user
        user_id = user.create(request.json)
        xray_recorder.current_segment().put_annotation('user_id', user_id)

        # Save other data in DDB
        UserData(user_id).create(request.json)
        res['user'] = user.get()

    except DuplicateEntityException:
        # The user already exists
        raise DuplicateEntityException('A user with that email address is already registered')

    except Exception as e:
        # Rollback
        try:
            user.delete()
        except NoSuchEntityException:
            pass
        except Exception as e2:
            raise e2 from e
        raise e

    res['authorization'] = user.login(password=request.json['password'])

    return res, 201


def metricise_values():
    if 'biometric_data' in request.json:
        if 'height' in request.json['biometric_data']:
            height = request.json['biometric_data']['height']
            if 'ft_in' in height and 'm' not in height:
                request.json['biometric_data']['height']['m'] = ftin_to_metres(height['ft_in'][0], height['ft_in'][1])
        if 'mass' in request.json['biometric_data']:
            mass = request.json['biometric_data']['mass']
            if 'lb' in mass and 'kg' not in mass:
                request.json['biometric_data']['mass']['kg'] = lb_to_kg(mass['lb'])


@user_app.route('/<uuid:user_id>/authorize', methods=['POST'])
@body_required({'session_token': str})
@xray_recorder.capture('routes.user.authorise')
def handle_user_authorise(user_id):
    auth = User(user_id).login(token=request.json['session_token'])
    return {'authorization': auth}


@user_app.route('/<uuid:user_id>/logout', methods=['POST'])
@self_authentication_required
@xray_recorder.capture('routes.user.logout')
def handle_user_logout(user_id):
    User(user_id).logout()
    return {'authorization': None}


@user_app.route('/<uuid:user_id>', methods=['PATCH'])  # TODO This was PUT
@authentication_required
@body_required({})
@xray_recorder.capture('routes.user.patch')
def update_user(user_id):
    xray_recorder.current_segment().put_annotation('user_id', user_id)

    if 'role' in request.json:
        raise UnauthorizedException('Cannot elevate user role')

    # Get the metric values for height and mass if only imperial values were given
    metricise_values()

    ret = User(user_id).patch(request.json)
    return {'user': ret}


@user_app.route('/<uuid:user_id>', methods=['DELETE'])
@authentication_required
@xray_recorder.capture('routes.user.delete')
def handle_delete_user(user_id):
    User(user_id).delete()
    return {'message': 'Success'}


@user_app.route('/<uuid:user_id>', methods=['GET'])
@authentication_required
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    return {'user': User(user_id).get()}


def _attempt_cognito_migration(user, email, password):
    # Check that we can still log in with the migration default password
    temp_authorisation = user.login(password=os.environ['MIGRATION_DEFAULT_PASSWORD'])

    # Check that the supplied password matches the one in Cognito.  Note that this does not require
    # us to have bcrypt or Flask-bcrypt installed in this codebase, but does require the `pgcrypto`
    # extension to be enabled in postgres.
    check_postgres = query_postgres(
        "SELECT id, password_digest=crypt(%s, password_digest) AS password_match FROM users WHERE email=%s",
        [password, email]
    )[0]

    if not check_postgres['password_match']:
        raise UnauthorizedException('Password does not match in Postgres')

    # Change the password in cognito
    user.change_password(
        temp_authorisation['AccessToken'],
        os.environ['MIGRATION_DEFAULT_PASSWORD'],
        password
    )

    # Record the date
    user.patch({'migrated_date': nowdate()})

    # And login as normal
    res = user.login(password=password)

    # update mongo collections to the new user_id
    url = "http://apis.{env}.fathomai.com/plans/1_0/misc/cognito_migration"
    body = {"legacy_user_id": check_postgres['id'],
            "user_id": user_id}
    headers = {
            'Content-Type': "application/json"
            }

    response = requests.request("PATCH", url, data=json.dumps(body), headers=headers)

    return res

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

