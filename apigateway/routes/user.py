from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError
from flask import Blueprint, request
import binascii
import boto3
import hashlib
import json
import os
import time

from fathomapi.api.config import Config
from fathomapi.comms.service import Service
from fathomapi.comms.legacy import query_postgres_sync
from fathomapi.comms.transport import send_ses_email
from fathomapi.utils.decorators import require
from fathomapi.utils.exceptions import DuplicateEntityException, UnauthorizedException, NoSuchEntityException, \
    ForbiddenException, ApplicationException, InvalidSchemaException, NoUpdatesException

from utils import ftin_to_metres, lb_to_kg
from models.account import Account
from models.user import User
from models.user_data import UserData
from models.device import Device
from utils import nowdate

push_notifications_table = boto3.resource('dynamodb').Table(Config.get('PUSHNOTIFICATIONS_DYNAMODB_TABLE_NAME'))
user_app = Blueprint('user', __name__)


@user_app.route('/login', methods=['POST'])  # TODO was /sign_in
@require.body({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.login')
def user_login():
    user = User(request.json['personal_data']['email'])
    user_record = user.get()

    try:
        authorisation = user.login(password=request.json['password'])
    except UnauthorizedException as e:
        if user_record['migrated_date'] is not None and user_record['migrated_date'] != 'completed':
            # Try migrating them
            try:
                authorisation = _attempt_cognito_migration(
                    user,
                    request.json['personal_data']['email'],
                    request.json['password']
                )
            except Exception as e2:
                print(e2)
                # Raise the original error
                raise e
        else:
            raise e

    return {
        'user': user_record,
        'authorization': authorisation
    }


@user_app.route('/', methods=['POST'])
@require.body({'personal_data': {'email': str}, 'password': str})
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
        request.json['email_verified'] = 'true'
    else:
        request.json['email_verified'] = 'false'
        request.json['_email_confirmation_code'] = binascii.b2a_hex(os.urandom(12)).decode()
        if 'migrated_date' in request.json:
            del request.json['migrated_date']

    # Get the metric values for height and mass if only imperial values were given
    metricise_values()

    if 'account_code' in request.json:
        try:
            account = Account.get_from_code(request.json['account_code'])
            xray_recorder.current_segment().put_annotation('account_id', account.id)
            request.json['account_ids'] = [account.id]
        except NoSuchEntityException:
            raise NoSuchEntityException('Unrecognised account_code')
    else:
        account = None

    user = User(request.json['personal_data']['email'])

    # This set of operations needs to be atomic, we don't want to have the user saved in Cognito (hence their email
    # address is 'squatted' and can't be re-registered) but their data not saved in DDB
    try:
        try:
            user.create(request.json)
        except DuplicateEntityException:
            # The user already exists
            raise DuplicateEntityException('A user with that email address is already registered')
        xray_recorder.current_segment().put_annotation('user_id', user.id)

        try:
            if account is not None:
                account.add_user(user.id)

            try:
                UserData(user.id).create(request.json)

            except Exception:
                _do_without_error(lambda: UserData(user.id).delete())
                raise
        except Exception:
            _do_without_error(lambda: account.remove_user(user.id))
            raise
    except Exception:
        _do_without_error(lambda: user.delete())
        raise

    # Send confirmation code
    # send_ses_email(
    #     request.json['personal_data']['email'],
    #     'Confirm your account',
    #     f'Your Fathomai email confirmation code is {request.json["_email_confirmation_code"]}'
    # )

    res = {
        'user': user.get(),
        'authorization': user.login(password=request.json['password']),
    }

    return res, 201


def _do_without_error(f):
    """
    Invoke a function, catching and ignoring all errors
    :param callable f:
    """
    try:
        f()
    except Exception as e:
        print(e)


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


@user_app.route('/forgot_password', methods=['POST'])
@require.body({'personal_data': {'email': str}})
@xray_recorder.capture('routes.user.forgotpassword')
def handle_user_forgot_password():
    user = User(request.json['personal_data']['email'])
    user.send_password_reset()
    return {'message': 'Success'}, 200


@user_app.route('/reset_password', methods=['POST'])
@require.body({'personal_data': {'email': str}, 'confirmation_code': str, 'password': str})
@xray_recorder.capture('routes.user.reset_password')
def handle_user_reset_password():
    user = User(request.json['personal_data']['email'])
    user.reset_password(request.json['confirmation_code'], request.json['password'])
    return {'message': 'Success'}, 200


@user_app.route('/<uuid:user_id>/authorize', methods=['POST'])
@require.body({'session_token': str})
@xray_recorder.capture('routes.user.authorise')
def handle_user_authorise(user_id):
    user = User(user_id)
    auth = user.login(token=request.json['session_token'])

    if 'timezone' in request.json:
        user.patch({'timezone': request.json['timezone']})

    return {'authorization': auth}


@user_app.route('/<uuid:user_id>/logout', methods=['POST'])
@require.authenticated.self
@xray_recorder.capture('routes.user.logout')
def handle_user_logout(user_id):
    User(user_id).logout()

    # De-affiliate all the user's devices
    devices = Device.get_many(owner_id=user_id)
    for device in devices:
        device.patch({'owner_id': None})

    return {'authorization': None}


@user_app.route('/<uuid:user_id>', methods=['PATCH'])  # TODO This was PUT
@require.authenticated.any
@require.body({})
@xray_recorder.capture('routes.user.patch')
def handle_user_patch(user_id):
    xray_recorder.current_segment().put_annotation('user_id', user_id)

    if 'role' in request.json:
        raise UnauthorizedException('Cannot elevate user role')

    # Get the metric values for height and mass if only imperial values were given
    metricise_values()

    ret = User(user_id).patch(request.json)
    return {'user': ret}


@user_app.route('/<uuid:user_id>', methods=['DELETE'])
@require.authenticated.any
@xray_recorder.capture('routes.user.delete')
def handle_user_delete(user_id):
    user = User(user_id)
    account_ids = user.get()['account_ids']
    for account_id in account_ids:
        account = Account(account_id)
        account.remove_user(user_id)
    UserData(user.id).delete()
    user.delete()
    return {'message': 'Success'}


@user_app.route('/<uuid:user_id>', methods=['GET'])
@require.authenticated.any
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    return {'user': User(user_id).get()}


@user_app.route('/<uuid:user_id>/change_password', methods=['POST'])
@require.authenticated.self
@require.body({'session_token': str, 'password': str, 'old_password': str})
@xray_recorder.capture('routes.user.change_password')
def handle_user_change_password(user_id):
    user = User(user_id)

    if request.json['password'] == request.json['old_password']:
        raise NoUpdatesException

    user.change_password(request.json['session_token'], request.json['old_password'], request.json['password'])

    return {'message': 'Success'}


@user_app.route('/<uuid:user_id>/verify_email', methods=['POST'])
@require.authenticated.self
@require.body({'confirmation_code': str})
@xray_recorder.capture('routes.user.verify_email')
def handle_user_verify_email(user_id):
    user = User(user_id)
    user.verify_email(request.json['confirmation_code'])
    return {'message': 'Success'}


def _attempt_cognito_migration(user, email, password):
    print('Attempting cognito migration')

    # Check that we can still log in with the migration default password
    try:
        temp_authorisation = user.login(password=Config.get('MIGRATION_DEFAULT_PASSWORD'))
    except UnauthorizedException:
        raise UnauthorizedException('Could not log in with migration default password')

    # Check that the supplied password matches the one in Cognito.  Note that this does not require
    # us to have bcrypt or Flask-bcrypt installed in this codebase, but does require the `pgcrypto`
    # extension to be enabled in postgres.
    check_postgres = query_postgres_sync(
        "SELECT id, replace(password_digest, '$2b$', '$2a$')=crypt(%s, replace(password_digest, '$2b$', '$2a$')) AS password_match FROM users WHERE email=%s",
        [password, email]
    )[0]

    if not check_postgres['password_match']:
        raise UnauthorizedException('Password does not match in Postgres')

    # Change the password in cognito
    user.change_password(
        temp_authorisation['session_token'],
        Config.get('MIGRATION_DEFAULT_PASSWORD'),
        password
    )

    # And login as normal
    res = user.login(password=password)

    # update mongo collections to the new user_id
    Service('plans', '1_0').call_apigateway_sync(
        method='PATCH',
        endpoint='misc/cognito_migration',
        body={"legacy_user_id": check_postgres['id'], "user_id": user.id},
        headers={'Content-Type': "application/json"}
    )

    # Mark migration as completed
    user.patch({'migrated_date': 'completed'})

    return res


@user_app.route('/<uuid:user_id>/notify', methods=['POST'])
@require.authenticated.service
@require.body({'message': str, 'call_to_action': str})
@xray_recorder.capture('routes.user.notify')
def handle_user_notify(user_id):
    devices = Device.get_many(owner_id=user_id)

    if request.json['call_to_action'] not in ['VIEW_PLAN', 'COMPLETE_DAILY_READINESS', 'COMPLETE_ACTIVE_RECOVERY', 'COMPLETE_ACTIVE_PREP']:
        raise InvalidSchemaException("`call_to_action` must be one of VIEW_PLAN, COMPLETE_DAILY_READINESS, COMPLETE_ACTIVE_RECOVERY, COMPLETE_ACTIVE_PREP")

    if len(devices) == 0:
        return {'message': f'No devices registered for user {user_id}'}, 540

    message = request.json['message']
    payload = {
        'message': message,
        'call_to_action': request.json['call_to_action'],
    }
    message_digest = hashlib.sha512(json.dumps(payload).encode()).hexdigest()
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
            device.send_push_notification(message, payload)
            statuses[device.id] = {'success': True, 'message': 'Success'}
        except ApplicationException as e:
            statuses[device.id] = {'success': False, 'message': str(e)}

    return statuses, 200

