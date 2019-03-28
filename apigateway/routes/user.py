from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError
from flask import Blueprint, request
import boto3
import hashlib
import json
import time
import datetime

from fathomapi.api.config import Config
from fathomapi.comms.transport import send_ses_email
from fathomapi.utils.decorators import require
from fathomapi.utils.exceptions import DuplicateEntityException, UnauthorizedException, NoSuchEntityException, \
    ForbiddenException, ApplicationException, InvalidSchemaException, NoUpdatesException

from utils import ftin_to_metres, lb_to_kg
from models.account import Account
from models.account_code import AccountCode
from models.user import User
from models.user_data import UserData
from models.device import Device
from utils import nowdate, format_date

push_notifications_table = boto3.resource('dynamodb').Table(Config.get('PUSHNOTIFICATIONS_DYNAMODB_TABLE_NAME'))
user_app = Blueprint('user', __name__)


@user_app.route('/login', methods=['POST'])
@require.body({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.login')
def user_login():
    try:
        user = User(request.json['personal_data']['email'])
        return {
            'user': user.get(),
            'authorization': user.login(password=request.json['password']),
        }
    except (NoSuchEntityException, UnauthorizedException):
        raise UnauthorizedException('Your email or password is incorrect.  Please try again.')


@user_app.route('/', methods=['POST'])
@require.body({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.post')
def create_user():
    """
    Creates a new user
    """
    # if 'role' in request.json and request.json['role'] != 'athlete':
    #     raise ForbiddenException('Cannot create user with elevated role')
    birth_date = format_date(request.json['personal_data']['birth_date'])
    now = datetime.datetime.now()
    cutoff_date = format_date(datetime.datetime(year=now.year - 13,
                                                month=now.month,
                                                day=now.day))
    if birth_date > cutoff_date:
        raise ForbiddenException('Sorry, Fathom is only for users 13 or older!')

    request.json['role'] = 'athlete'

    if 'User-Agent' in request.headers and request.headers['User-Agent'] == 'biometrix/cognitomigrator':
        request.json['migrated_date'] = nowdate()
        request.json['email_verified'] = 'true'
    else:
        # request.json['email_verified'] = 'false'
        # request.json['_email_confirmation_code'] = binascii.b2a_hex(os.urandom(12)).decode()
        request.json['email_verified'] = 'true'
        if 'migrated_date' in request.json:
            del request.json['migrated_date']

    # Get the metric values for height and mass if only imperial values were given
    metricise_values()

    if 'account_code' in request.json:
        try:
            account_code = AccountCode(request.json['account_code']).get()
            account = Account(account_code['account_id'])
            xray_recorder.current_subsegment().put_annotation('account_id', account.id)
            request.json['account_ids'] = [account.id]
            request.json['role'] = account_code['role']
        except NoSuchEntityException:
            raise NoSuchEntityException('Invalid account code.  Please try again')
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
        except ClientError as e:
            if 'InvalidParameterException' in str(e) and 'username' in str(e):
                raise InvalidSchemaException(f'"{user.id}" is not a valid username')
        xray_recorder.current_subsegment().put_annotation('user_id', user.id)

        try:
            UserData(user.id).create(request.json)
            try:
                if account is not None:
                    account.add_user(user.id, request.json['role'])
            except Exception:
                _do_without_error(lambda: account.remove_user(user.id, request.json['role']))
                raise

        except Exception:
            _do_without_error(lambda: UserData(user.id).delete())
            raise
    except DuplicateEntityException:
        raise
    except Exception:
        _do_without_error(lambda: user.delete())
        raise

    # Send confirmation code
    if '_email_confirmation_code' in request.json:
        send_ses_email(
            request.json['personal_data']['email'],
            'Confirm your account',
            f'Your Fathomai email confirmation code is {request.json["_email_confirmation_code"]}'
        )

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

    try:
        user.send_password_reset()
    except ClientError as e:
        if 'UserNotFoundException' in str(e):
            raise NoSuchEntityException('No account with that email address exists.')
        raise e

    return {'message': 'Success'}, 200


@user_app.route('/reset_password', methods=['POST'])
@require.body({'personal_data': {'email': str}, 'confirmation_code': str, 'password': str})
@xray_recorder.capture('routes.user.reset_password')
def handle_user_reset_password():
    user = User(request.json['personal_data']['email'])

    try:
        user.reset_password(request.json['confirmation_code'], request.json['password'])
    except ClientError as e:
        if 'ExpiredCodeException' in str(e):
            raise UnauthorizedException('Invalid or expired reset code.  Please request a new code.')
        raise e

    return {'message': 'Success'}, 200


@user_app.route('/<uuid:user_id>/authorize', methods=['POST'])
@require.body({'session_token': str})
@xray_recorder.capture('routes.user.authorise')
def handle_user_authorise(user_id):
    user = User(user_id)

    try:
        auth = user.login(token=request.json['session_token'])
    except ClientError as e:
        if 'NotAuthorizedException' in str(e):
            raise ForbiddenException('Refresh token has been revoked.  Please log in again.')
        raise e

    if 'timezone' in request.json:
        user.patch({'timezone': request.json['timezone']})

    return {'authorization': auth}


@user_app.route('/<uuid:user_id>/logout', methods=['POST'])
@require.authenticated.self
@xray_recorder.capture('routes.user.logout')
def handle_user_logout(user_id):
    User(user_id).logout()

    # De-affiliate all the user's devices
    for device in Device.get_many(owner_id=user_id):
        device.patch({'owner_id': None})

    return {'authorization': None}


@user_app.route('/<uuid:user_id>', methods=['PATCH'])
@require.authenticated.any
@require.body({})
@xray_recorder.capture('routes.user.patch')
def handle_user_patch(user_id):
    xray_recorder.current_subsegment().put_annotation('user_id', user_id)

    if 'role' in request.json:
        # raise UnauthorizedException('Cannot elevate user role')
        del request.json['role']

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
        account.remove_user(user_id, 'athlete')
    UserData(user.id).delete()
    user.delete()
    return {'message': 'Success'}


@user_app.route('/<uuid:user_id>', methods=['GET'])
@require.authenticated.any
@xray_recorder.capture('routes.user.get')
def handle_user_get(user_id):
    user = User(user_id).get()
    if 'get_team' in request.args and request.args['get_team'] in  ['TRUE', 'True', 'true']:
        accounts = user['account_ids']
        if len(accounts) == 0:
            raise NoSuchEntityException("User does not belong to a team")
        account_users = []
        for account_id in accounts:
            account = Account(account_id).get()
            account_users.append({'account': account, 'users': [ud.get() for ud in list(UserData.get_many(id=account['users']))]})
        return {'user': user, 'accounts': account_users}

    return {'user': user}


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


@user_app.route('/<uuid:user_id>/join_account', methods=['POST'])
@require.authenticated.self
@require.body({'account_code': str})
@xray_recorder.capture('routes.user.join_account')
def handle_user_join_account(user_id):
    user = User(user_id)
    try:
        account_code = AccountCode(request.json['account_code']).get()
    except NoSuchEntityException:
        raise NoSuchEntityException('Invalid account code. Please try again.')
    account = Account(account_code['account_id'])

    if user.get()['role'] != account_code['role'] and len(user.get()['account_ids']) > 0:
        raise NotImplementedError(f'User is currently {user.get()["role"]}, cannot use {account_code["role"]} code.')

    account.add_user(user.id, account_code['role'])
    return {'message': 'Success', 'account': account.get()}


@user_app.route('/<uuid:user_id>/notify', methods=['POST'])
@require.authenticated.service
@require.body({'message': str, 'call_to_action': str})
@xray_recorder.capture('routes.user.notify')
def handle_user_notify(user_id):
    devices = list(Device.get_many(owner_id=user_id))

    if request.json['call_to_action'] not in ['VIEW_PLAN', 'COMPLETE_DAILY_READINESS', 'COMPLETE_ACTIVE_RECOVERY', 'COMPLETE_ACTIVE_PREP']:
        raise InvalidSchemaException("`call_to_action` must be one of VIEW_PLAN, COMPLETE_DAILY_READINESS, COMPLETE_ACTIVE_RECOVERY, COMPLETE_ACTIVE_PREP")

    if len(devices) == 0:
        return {'message': f'No devices registered for user {user_id}'}, 540

    message = request.json['message']
    if request.json['call_to_action'] == 'COMPLETE_DAILY_READINESS':
        user = User(user_id).get()
        first_name = user['personal_data']['first_name']
        message = message.format(first_name=first_name)
    payload = {
        'message': message,
        'call_to_action': request.json['call_to_action'],
    }
    if 'last_updated' in request.json:
        payload['last_updated'] = request.json['last_updated']
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
    if 'last_updated' in payload:
        del payload['last_updated']
    for device in devices:
        try:
            device.send_push_notification(message, payload)
            statuses[device.id] = {'success': True, 'message': 'Success'}
        except ApplicationException as e:
            statuses[device.id] = {'success': False, 'message': str(e)}

    return statuses, 200
