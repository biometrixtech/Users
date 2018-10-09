from aws_xray_sdk.core import xray_recorder
from flask import Blueprint
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
    Service('users', Config.get('API_VERSION')).call_apigateway_sync('POST', '/misc/activeusers')

    return {'status': 'Success'}, 200


@misc_app.route('/activeusers', methods=['POST'])
@require.authenticated.service
@xray_recorder.capture('routes.misc.activeusers')
def handle_activeusers():
    # This route will be invoked daily.  It should scan to find users which meet
    # some definition of 'active', and for each one should push to the plans service with them

    # TODO definition of active
    active_users = User.get_many()

    plans_service = Service('plans', '1_0')
    now = datetime.datetime.now()
    for user in active_users:
        print(user)
        user_data = UserData(user.id).get()
        print(user_data)
        # user_data = user.get()
        if "timezone" in user_data:
            body = {"timezone": timezone}
        else:
            body = {"timezone": "-05:00"}
        print(user.id, body)
        execute_at = now + datetime.timedelta(seconds=random.randint(0, 60))
        print(f"plans_service.call_apigateway_async('POST', f'/athlete/{user.id}/active', body=body, execute_at=execute_at))")
        # plans_service.call_apigateway_async('POST', f'/athlete/{user.id}/active', body=body, execute_at=execute_at)

    return {'status': 'Success'}

