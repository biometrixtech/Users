from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request

from decorators import authentication_required, body_required, self_authentication_required
from exceptions import DuplicateEntityException, UnauthorizedException, NoSuchEntityException, \
    ForbiddenException
from utils import ftin_to_metres, lb_to_kg
from models.user import User
from models.user_data import UserData

user_app = Blueprint('user', __name__)


@user_app.route('/login', methods=['POST'])  # TODO was /sign_in
@body_required({'personal_data': {'email': str}, 'password': str})
@xray_recorder.capture('routes.user.login')
def user_login():
    user = User(request.json['personal_data']['email'])
    return {
        'user': user.get(),
        'authorization': user.login(password=request.json['password'])  # This throws AuthorizationException
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
