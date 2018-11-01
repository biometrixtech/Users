from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import uuid

from fathomapi.utils.decorators import require
from fathomapi.utils.exceptions import DuplicateEntityException

from models.account import Account

account_app = Blueprint('account', __name__)


@account_app.route('/', methods=['POST'])
@require.body({'name': str, 'seats': int})
@require.authenticated.service
@xray_recorder.capture('routes.account.create')
def create_account():

    # Since codes are generated randomly, there is a small (about one in 3.3-billion-divided-by-number-of-existing-codes)
    # of a clash.  Retrying a few times makes the probability of failing to secure a unique code essentially zero.
    for i in range(5):
        request.json['code'] = Account.generate_code()

        # Generating an id algorithmically from the code, means that the uniqueness constraint on id extends to
        # enforcing uniqueness of the code
        account = Account(str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://schema.fathomai.com/schemas/account/{request.json['code']}")))
        try:
            ret = account.create(request.json)
            break
        except DuplicateEntityException:
            continue
    else:
        return {'message': 'Could not generate a unique account code.  Please try again'}, 500

    return {'account': ret}, 201


@account_app.route('/<uuid:account_id>', methods=['PATCH'])
@require.authenticated.service
@require.body({})
@xray_recorder.capture('routes.account.patch')
def update_account(account_id):
    xray_recorder.current_subsegment().put_annotation('account_id', account_id)

    ret = Account(account_id).patch(request.json)
    return {'account': ret}


@account_app.route('/<uuid:account_id>', methods=['DELETE'])
@require.authenticated.service
@xray_recorder.capture('routes.account.delete')
def handle_delete_account(account_id):
    Account(account_id).delete()
    return {'message': 'Success'}, 202


@account_app.route('/<uuid:account_id>', methods=['GET'])
@require.authenticated.any
@xray_recorder.capture('routes.account.get')
def handle_account_get(account_id):
    return {'account': Account(account_id).get()}
