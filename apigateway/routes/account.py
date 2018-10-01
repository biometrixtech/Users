from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import uuid

from fathomapi.utils.decorators import require

from models.account import Account

account_app = Blueprint('account', __name__)


@account_app.route('/', methods=['POST'])
@require.body({'name': str, 'seats': int})
@require.authenticated.service
@xray_recorder.capture('routes.account.create')
def create_account():
    return {'account': Account(str(uuid.uuid4())).create(request.json)}, 201


@account_app.route('/<uuid:account_id>', methods=['PATCH'])
@require.authenticated.service
@require.body({})
@xray_recorder.capture('routes.account.patch')
def update_account(account_id):
    xray_recorder.current_segment().put_annotation('account_id', account_id)

    ret = Account(account_id).patch(request.json)
    return {'account': ret}


@account_app.route('/<uuid:account_id>', methods=['DELETE'])
@require.authenticated.service
@xray_recorder.capture('routes.account.delete')
def handle_delete_account(account_id):
    Account(account_id).delete()
    return {'message': 'Success'}


@account_app.route('/<uuid:account_id>', methods=['GET'])
@require.authenticated.any
@xray_recorder.capture('routes.account.get')
def handle_account_get(account_id):
    return {'account': Account(account_id).get()}
