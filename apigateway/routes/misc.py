from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import datetime
import random

from fathomapi.api.config import Config
from fathomapi.comms.service import Service
from fathomapi.utils.decorators import require

from models.user import User
from models.user_data import UserData

misc_app = Blueprint('misc', __name__)


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

    plans_service = Service('plans', '2_0')
    now = datetime.datetime.now()
    calls = []
    for user in active_users:
        try:
            user_datum = next(ud for ud in user_data if ud.id == user.id)
        except StopIteration:
            print(f"user not found {user.id}")
            continue
        body = {"timezone": user_datum.get().get('timezone', None) or "-05:00"}

        calls.append({'method': 'POST', 'endpoint': f'/athlete/{user.id}/active', 'body': body})

    execute_at = now + datetime.timedelta(seconds=random.randint(0, 60))
    plans_service.call_apigateway_async_multi(calls=calls, execute_at=execute_at)

    if user_generator.value is not None:
        print('Triggering next batch')
        self_service = Service('users', Config.get('API_VERSION'))
        self_service.call_apigateway_async('POST', '/misc/activeusers', body={'next_token': user_generator.value})

    return {'status': 'Success'}

