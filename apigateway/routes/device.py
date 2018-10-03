from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import boto3

from fathomapi.api.converters import UuidConverter
from fathomapi.utils.decorators import require

from models.device import Device


device_app = Blueprint('device', __name__)

sns_client = boto3.client('sns')


@device_app.route('/<uuid:device_id>', methods=['POST'])
@require.authenticated.any  # Adds principal_id to function call
@require.body({'device_type': str, 'push_notifications': [None, {'token': [None, str], 'enabled': bool}]})
@xray_recorder.capture('routes.device.register')
def handle_device_register(device_id, principal_id=None):
    request.json['owner_id'] = principal_id

    device = Device(device_id)
    device.create(request.json)

    cert_id, cert_pem, cert_pub, cert_priv = device.create_key()

    return {
        'device': device.get(),
        'certificate': {
            'id': cert_id,
            'pem': cert_pem,
            'public_key': cert_pub,
            'private_key': cert_priv,
        }
    }, 201


@device_app.route('/<uuid:device_id>', methods=['PATCH'])
@require.authenticated.any
@require.body({'owner_id': [None, UuidConverter], 'push_notifications': [None, {'token': [None, str], 'enabled': bool}]})
@xray_recorder.capture('routes.device.patch')
def handle_device_patch(device_id):
    device = Device(device_id)
    modified = device.patch(request.json)

    if modified:
        return {"message": "Update successful"}, 200
    else:
        return {"message": "No updates"}, 204


@device_app.route('/<uuid:device_id>', methods=['GET'])
@require.authenticated.any
@xray_recorder.capture('routes.device.get')
def handle_device_get(device_id):
    return {'device': Device(device_id).get()}
