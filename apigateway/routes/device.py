from aws_xray_sdk.core import xray_recorder
from flask import Blueprint, request
import boto3
import datetime
import os
from botocore.exceptions import ClientError

from decorators import authentication_required, authenticate_user_jwt
from exceptions import InvalidSchemaException, NoSuchEntityException, UnauthorizedException, DuplicateEntityException
from utils import validate_uuid4


device_app = Blueprint('device', __name__)
iot_client = boto3.client('iot')


@device_app.route('/<uuid:device_id>', methods=['POST'])
@authentication_required
@xray_recorder.capture('routes.device.register')
def handle_device_register(device_id):
    if not request.json:
        raise InvalidSchemaException('Body must be JSON formatted')
    for key in ['device_type']:
        if key not in request.json:
            raise InvalidSchemaException(f'Missing required field {key}')

    owner_id = authenticate_user_jwt(request.headers['Authorization'])

    # Make sure the device isn't already registered
    try:
        iot_client.describe_thing(thingName=device_id)
    except ClientError as e:
        if 'ResourceNotFound' not in str(e):
            iot_client.create_thing(
                thingName=device_id,
                thingTypeName='users-{ENVIRONMENT}-device'.format(**os.environ),
                attributePayload={
                    'attributes': {
                        'device_type': request.json['device_type'],
                        'owner_id': owner_id,
                    },
                }
            )

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

    return {
        'device': {
            'id': device_id,
            'type': request.json['device_type'],
        },
        'certificate': {
            'id': certificate_response['certificateId'],
            'pem': certificate_response['certificatePem'],
            'public_key': certificate_response['keyPair']['PublicKey'],
            'private_key': certificate_response['keyPair']['PrivateKey'],
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
        else:
            raise InvalidSchemaException('owner_id must be uuid or none')

    if modified:
        return {"message": "Update successful"}, 200
    else:
        return {"message": "No updates"}, 204
