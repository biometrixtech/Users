from aws_xray_sdk.core import xray_recorder
from flask import Blueprint
import datetime
import random

from fathomapi.comms.service import Service

user_app = Blueprint('misc', __name__)


@user_app.route('/activeusers', methods=['POST'])
@xray_recorder.capture('routes.misc.activeusers')
def user_login():
    # This route will be called daily via a CloudWatch Scheduled Event.  It should scan to find users which meet
    # some definition of 'active', and for each one should push to the plans service with them

    # TODO
    active_users = []

    plans_service = Service('plans', '1_0')
    now = datetime.datetime.now()
    for user in active_users:
        execute_at = now + datetime.timedelta(seconds=random.randint(0, 60))
        plans_service.call_apigateway_async('POST', f'/athlete/{user.id}/active', execute_at=execute_at)

    return {'status': 'Success'}
