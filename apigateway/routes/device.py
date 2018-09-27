from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import boto3
import json
from botocore.exceptions import ClientError

from fathomapi.api.config import Config
from fathomapi.api.converters import UuidConverter
from fathomapi.utils.decorators import require
from fathomapi.utils.exceptions import InvalidSchemaException, NoSuchEntityException


device_app = Blueprint('device', __name__)

iot_client = boto3.client('iot')
sns_client = boto3.client('sns')


@device_app.route('/<uuid:device_id>', methods=['POST'])
@require.authenticated.any  # Adds principal_id to function call
@require.body({'device_type': str, 'push_notifications': [None, {'token': str, 'enabled': bool}]})
@xray_recorder.capture('routes.device.register')
def handle_device_register(device_id, principal_id=None):
    device_type = request.json['device_type']
    owner_id = principal_id

    thing_attributes = get_or_create_thing(device_id, device_type, owner_id)

    cert_id, cert_pem, cert_pub, cert_priv = create_iot_keys(device_id)

    if 'push_notifications' in request.json:
        update_push_notification_settings(
            device_id,
            device_type,
            request.json['push_notifications']['token'],
            old_endpoint_arn=thing_attributes.get('push_notifications.endpoint', thing_attributes.get('push_notifications_endpoint', None)),
            enabled=request.json['push_notifications']['enabled'],
            owner_id=owner_id,
        )

    return {
        'device': {
            'id': device_id,
            'type': device_type,
        },
        'certificate': {
            'id': cert_id,
            'pem': cert_pem,
            'public_key': cert_pub,
            'private_key': cert_priv,
        }
    }, 201


@device_app.route('/<uuid:device_id>', methods=['PATCH'])
@require.authenticated.any
@require.body({'owner_id': [None, UuidConverter], 'push_notifications': [None, {'token': str, 'enabled': bool}]})
@xray_recorder.capture('routes.device.affiliate')
def handle_device_patch(device_id):
    existing_attributes = get_or_create_thing(
        device_id,
        request.json.get('device_type', None),
        request.json.get('owner_id', None)
    )

    modified = False
    if 'owner_id' in request.json:
        owner_id = request.json['owner_id']
        try:
            iot_client.update_thing(
                thingName=device_id,
                attributePayload={
                    'attributes': {'owner_id': '' if owner_id is None else owner_id},
                    'merge': True
                }
            )
            modified = True
        except ClientError as e:
            if 'ResourceNotFound' in str(e):
                raise NoSuchEntityException('No device with that id')
            else:
                raise
    else:
        owner_id = existing_attributes.get('owner_id', None)

    if 'push_notifications' in request.json:
        if request.json['push_notifications']['token'] is not None:
            update_push_notification_settings(
                device_id,
                existing_attributes['device_type'],
                request.json['push_notifications']['token'],
                old_endpoint_arn=existing_attributes.get('push_notifications.endpoint', existing_attributes.get('push_notifications_endpoint', None)),
                enabled=request.json['push_notifications']['enabled'],
                owner_id=owner_id
            )
        else:
            delete_push_notification_settings(device_id)
        modified = True

    if modified:
        return {"message": "Update successful"}, 200
    else:
        return {"message": "No updates"}, 204


def get_or_create_thing(device_id, device_type, owner_id):
    try:
        return iot_client.describe_thing(thingName=device_id)['attributes']
    except ClientError as e:
        if 'ResourceNotFound' in str(e):
            print(f'Creating thing {device_id} with device_type={device_type}, owner_id={owner_id}')
            attributes = {
                'device_type': device_type,
                'owner_id': owner_id,
            }
            iot_client.create_thing(
                thingName=device_id,
                thingTypeName=f'users-{Config.get("ENVIRONMENT")}-device',
                attributePayload={'attributes': attributes}
            )
            return attributes
        else:
            raise


def create_iot_keys(device_id):
    certificate_response = iot_client.create_keys_and_certificate(setAsActive=True)

    iot_client.attach_thing_principal(
        thingName=device_id,
        principal=certificate_response['certificateArn']
    )

    iot_client.add_thing_to_thing_group(
        thingGroupName='users-{Config.get("ENVIRONMENT")}-device',
        thingName=device_id,
    )

    iot_client.attach_principal_policy(
        policyName=Config.get('IOT_POLICY_NAME'),
        principal=certificate_response['certificateArn']
    )

    return (
        certificate_response['certificateId'],
        certificate_response['certificatePem'],
        certificate_response['keyPair']['PublicKey'],
        certificate_response['keyPair']['PrivateKey']
    )


def delete_push_notification_settings(device_id):
    device_attributes = iot_client.describe_thing(thingName=device_id)['attributes']
    if 'push_notifications.endpoint' in device_attributes or 'push_notifications_endpoint' in device_attributes:
        sns_client.delete_endpoint(EndpointArn=device_attributes.get('push_notifications.endpoint', device_attributes['push_notifications_endpoint']))
        iot_client.update_thing(
            thingName=device_id,
            attributePayload={
                'attributes': {
                    'push_notifications_enabled': '',
                    'push_notifications_endpoint': '',
                    'push_notifications.enabled': '',
                    'push_notifications.endpoint': '',
                },
                'merge': True
            }
        )


def update_push_notification_settings(device_id, device_type, token, old_endpoint_arn=None, enabled=True, owner_id=None):
    # Add/update endpoint
    enabled = bool(enabled)
    attributes = {'Enabled': 'true' if enabled else 'false'}
    custom_user_data = {'Platform': device_type}

    if owner_id is not None:
        custom_user_data['UserId'] = owner_id

    if device_type == 'ios':
        application_arn = Config.get('SNS_APPLICATION_ARN_IOS')
    elif device_type == 'android':
        application_arn = Config.get('SNS_APPLICATION_ARN_ANDROID')
    else:
        raise InvalidSchemaException('device_type must be either ios or android')

    if old_endpoint_arn is not None:
        sns_client.delete_endpoint(EndpointArn=old_endpoint_arn)

    res = sns_client.create_platform_endpoint(
        PlatformApplicationArn=application_arn,
        Token=token,
        Attributes=attributes,
        CustomUserData=json.dumps(custom_user_data)
    )

    iot_client.update_thing(
        thingName=device_id,
        attributePayload={
            'attributes': {
                'push_notifications.enabled': '1' if enabled else '0',
                'push_notifications.endpoint': res['EndpointArn'],
                'push_notifications_enabled': '',
                'push_notifications_endpoint': '',
            },
            'merge': True
        }
    )

