from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import boto3
import datetime
import os
from botocore.exceptions import ClientError

from decorators import authentication_required, authenticate_user_jwt
from exceptions import InvalidSchemaException, NoSuchEntityException
from utils import validate_uuid4


device_app = Blueprint('device', __name__)
iot_client = boto3.client('iot')
pinpoint_client = boto3.client('pinpoint', region_name='us-east-1')


@device_app.route('/<uuid:device_id>', methods=['POST'])
@authentication_required
@xray_recorder.capture('routes.device.register')
def handle_device_register(device_id):
    if not request.json:
        raise InvalidSchemaException('Body must be JSON formatted')

    if 'device_type' not in request.json:
        raise InvalidSchemaException('Missing required field device-type')
    device_type = request.json['device_type']

    if 'push_notification' in request.json:
        if 'token' not in request.json['push_notification'] or 'enabled' not in request.json['push_notification']:
            raise InvalidSchemaException('push_notification config must have `token` and `enabled` keys')

    owner_id = authenticate_user_jwt(request.headers['Authorization'])

    # Make sure the device isn't already registered
    try:
        iot_client.describe_thing(thingName=device_id)
    except ClientError as e:
        if 'ResourceNotFound' in str(e):
            iot_client.create_thing(
                thingName=device_id,
                thingTypeName='users-{ENVIRONMENT}-device'.format(**os.environ),
                attributePayload={
                    'attributes': {
                        'device_type': device_type,
                        'owner_id': owner_id,
                    },
                }
            )

    cert_id, cert_pem, cert_pub, cert_priv = create_iot_keys(device_id)

    if 'push_notifications' in request.json:
        update_push_notification_settings(
            device_id,
            request.json['push_notifications']['token'],
            request.json['push_notifications']['enabled'],
            device_type=device_type,
            owner_id=owner_id
        )

    return {
        'device': {
            'id': device_id,
            'type': request.json['device_type'],
        },
        'certificate': {
            'id': cert_id,
            'pem': cert_pem,
            'public_key': cert_pub,
            'private_key': cert_priv,
        }
    }, 201


@device_app.route('/<uuid:device_id>', methods=['PATCH'])
@authentication_required
@xray_recorder.capture('routes.device.affiliate')
def handle_device_patch(device_id):
    if not request.json:
        raise InvalidSchemaException('Body must be JSON formatted')

    modified = False
    if 'owner_id' in request.json:
        owner_id = request.json['owner_id']
        if owner_id is None or validate_uuid4(owner_id):
            try:
                iot_client.update_thing(
                    thingName=device_id,
                    attributePayload={'attributes': {'owner_id': '' if owner_id is None else owner_id}}
                )
                modified = True
            except ClientError as e:
                if 'ResourceNotFound' in str(e):
                    raise NoSuchEntityException('No device with that id')
                else:
                    raise
            # FIXME need to update Pinpoint user record
        else:
            raise InvalidSchemaException('owner_id must be uuid or none')

    if 'push_notification' in request.json:
        update_push_notification_settings(
            device_id,
            request.json['push_notifications']['token'],
            request.json['push_notifications']['enabled'],
        )


    if modified:
        return {"message": "Update successful"}, 200
    else:
        return {"message": "No updates"}, 204


def create_iot_keys(device_id):
    certificate_response = iot_client.create_keys_and_certificate(setAsActive=True)

    iot_client.attach_thing_principal(
        thingName=device_id,
        principal=certificate_response['certificateArn']
    )

    iot_client.add_thing_to_thing_group(
        thingGroupName='users-{ENVIRONMENT}-device'.format(**os.environ),
        thingName=device_id,
    )

    iot_client.attach_principal_policy(
        policyName=os.environ['IOT_POLICY_NAME'],
        principal=certificate_response['certificateArn']
    )

    return (
        certificate_response['certificateId'],
        certificate_response['certificatePem'],
        certificate_response['keyPair']['PublicKey'],
        certificate_response['keyPair']['PrivateKey']
    )


def update_push_notification_settings(device_id, token, enabled=True, device_type=None, owner_id=None):

    if token is None:
        # Delete endpoint
        enabled = None
        pinpoint_client.delete_endpoint(
            ApplicationId=os.environ['PINPOINT_APP_ID'],
            EndpointId=device_id,
        )

    else:
        # Add/update endpoint
        enabled = bool(enabled)
        endpoint_request = {
            'Address': token,
            'ChannelType': 'APNS_SANDBOX' if os.environ['ENVIRONMENT'] == 'dev' else 'APNS',
            'OptOut': 'ALL' if not enabled else 'NONE'
        }
        if device_type is not None:
            endpoint_request['Demographic'] = {'Platform': device_type}
        if owner_id is not None:
            endpoint_request['User'] = {'UserId': owner_id}

        pinpoint_client.update_endpoint(
            ApplicationId=os.environ['PINPOINT_APP_ID'],
            EndpointId=device_id,
            EndpointRequest=endpoint_request
        )

    iot_client.update_thing(
        thingName=device_id,
        attributePayload={'attributes': {'push_notifications': '1' if enabled else '0'}}
    )

