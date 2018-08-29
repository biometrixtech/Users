from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request

from decorators import authentication_required, body_required, self_authentication_required
from exceptions import DuplicateEntityException

from models.user import User
from models.user_data import UserData

user_app = Blueprint('user', __name__)


@user_app.route('/login', methods=['POST'])  # TODO was /sign_in
@body_required({'email': str, 'password': str})
@xray_recorder.capture('routes.user.login')
def user_login():
    user = User(request.json['email'])
    return {
        'user': user.get(),
        'authorization': user.login(password=request.json['password'])  # This throws AuthorizationException
    }


@user_app.route('/', methods=['POST'])
@body_required({'email': str})
@xray_recorder.capture('routes.user.post')
def create_user():
    """
    Creates a new user
    """
    request.json['role'] = 'athlete'  # TODO
    user = User(request.json['email'])

    res = {'user': {}}

    # This pair of operations needs to be atomic, we don't want to have the user saved in Cognito (hence their email
    # address is 'squatted' and can't be re-registered) but their data not saved in DDB
    try:
        # Create Cognito user
        user_obj = user.create(request.json)
        xray_recorder.current_segment().put_annotation('user_id', user_obj['id'])
        res['user'].update(user_obj)

        # Save other data in DDB
        user_data = UserData(user_obj['id']).create(request.json)
        res['user'].update(user_data)

    except DuplicateEntityException:
        # The user already exists
        raise DuplicateEntityException('A user with that email address is already registered')

    except Exception:
        # Rollback
        user.delete()
        raise

    res['authorization'] = user.login(password=request.json['password'])

    return res, 201


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
@xray_recorder.capture('routes.user.patch')
def update_user(user_id):
    xray_recorder.current_segment().put_annotation('user_id', user_id)
    ret = UserData(user_id).patch(request.json)
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
    ret = {'user': User(user_id).get()}
    return ret
