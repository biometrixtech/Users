from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import datetime
import random
import os

from fathomapi.api.config import Config
from fathomapi.comms.service import Service
from fathomapi.utils.decorators import require

from models.user import User
from models.user_data import UserData

misc_app = Blueprint('misc', __name__)
PLANS_API_VERSION = os.environ['PLANS_API_VERSION']

@misc_app.route('/dailycron', methods=['POST'])
@xray_recorder.capture('routes.misc.dailycron')
def handle_dailycron():
    # This route will be called daily via a CloudWatch Scheduled Event.
    Service('users', Config.get('API_VERSION')).call_apigateway_sync('POST', '/misc/activeusers', body={})

    return {'status': 'Success'}, 200


@misc_app.route('/activeusers', methods=['POST'])
@require.authenticated.service
@require.body({})
@xray_recorder.capture('routes.misc.activeusers')
def handle_activeusers():
    # This route will be invoked daily.  It should scan to find users which meet
    # some definition of 'active', and for each one should push to the plans service with them

    # TODO definition of active
    user_generator = User.get_many(next_token=request.json.get('next_token', None), max_items=100)
    active_users = [user for user in user_generator]
    print(f'{len(active_users)} active users (in this batch)')

    user_data = list(UserData.get_many(id=[user.id for user in active_users]))

    plans_service = Service('plans', PLANS_API_VERSION)
    now = datetime.datetime.now()
    calls = []
    for user in active_users:
        try:
            user_datum = next(ud for ud in user_data if ud.id == user.id)
        except StopIteration:
            print(f"user not found {user.id}")
            continue
        body = {"timezone": user_datum.get().get('timezone', None) or "-05:00"}
        plans_api_version = user_datum.get().get('plans_api_version', None) or '4_3'
        if plans_api_version == '4_3':  # user after 4_3 will be scheduled directly through plans
            calls.append({'method': 'POST', 'endpoint': f'/athlete/{user.id}/active', 'body': body})
        else:
            print(f"skipping user {user.id} because plans api version is {plans_api_version}")

    plans_service.call_apigateway_async_multi(calls=calls, jitter=10 * 60)

    if user_generator.value is not None:
        print('Triggering next batch')
        self_service = Service('users', Config.get('API_VERSION'))
        self_service.call_apigateway_async('POST', '/misc/activeusers', body={'next_token': user_generator.value}, execute_at=now + datetime.timedelta(seconds=60))

    return {'status': 'Success'}

