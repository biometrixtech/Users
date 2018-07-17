from aws_xray_sdk.core import xray_recorder
from flask import Blueprint
import os


config_app = Blueprint('config', __name__)


@config_app.route('/', methods=['GET'])
@xray_recorder.capture('routes.config.get')
def handle_config_get():
    return {
        'pinpoint_app_id': os.environ['PINPOINT_APP_ID']
    }
