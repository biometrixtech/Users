from botocore.exceptions import ClientError
import boto3
import json

from fathomapi.api.config import Config
from fathomapi.models.iot_entity import IotEntity
from fathomapi.utils.exceptions import NoSuchEntityException, UnauthorizedException, InvalidSchemaException

_iot_client = boto3.client('iot')
_sns_client = boto3.client('sns')


class Device(IotEntity):
        
    @property
    def thing_type(self):
        return Config.get('DEVICES_THING_TYPE')

    @property
    def push_notifications_endpoint(self):
        return self.get()['push_notifications']['endpoint']

    @property
    def push_notifications_enabled(self):
        return self.get()['push_notifications']['enabled']

    def create(self, body):
        self.validate('PUT', body)
        self._upsert(body)

    def patch(self, body):
        self.validate('PATCH', body)
        self._upsert(body)

    def _upsert(self, body):
        existing_attributes = self._get_or_create_thing(
            body.get('device_type', None),
            body.get('owner_id', None)
        )

        modified = False
        if 'owner_id' in body:
            owner_id = body['owner_id']
            try:
                _iot_client.update_thing(
                    thingName=self.id,
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

        if 'push_notifications' in body:
            if body['push_notifications'].get('token', None) is not None:
                self._update_push_notification_settings(
                    existing_attributes['device_type'],
                    body['push_notifications']['token'],
                    old_endpoint_arn=self._get_existing_push_notification_endpoint(existing_attributes),
                    enabled=body['push_notifications']['enabled'],
                    owner_id=owner_id
                )
            else:
                self._delete_push_notification_settings()
            modified = True

        return modified

    def get(self):
        res = super().get()
        del res['push_notifications']['endpoint']
        return res

    def delete(self):
        raise NotImplementedError

    def send_push_notification(self, message, payload):
        message = str(message)

        if self.push_notifications_endpoint is None:
            raise NoSuchEntityException(f'No push notification endpoint configured for device {self.id}')

        if not self.push_notifications_enabled:
            raise UnauthorizedException(f'Push notifications disabled for device {self.id}')

        print(f'Sending notification "{message}" to endpoint {self.push_notifications_endpoint}')
        payload = {
            'default': message,
            'GCM': json.dumps({
                "data": {
                    "message": message,
                    "biometrix": payload
                },
                "time_to_live": 3600,
                "collapse_key": "YOUR_CUSTOM_CATEGORY"
            }),
            "APNS": json.dumps({
                "aps": {
                    "alert": message,
                    "sound": "default",
                    "badge": 1,
                    "category": "YOUR_CUSTOM_CATEGORY",
                    "content-available": 1
                },
                "biometrix": payload
            }),
            "APNS_SANDBOX": json.dumps({
                "aps": {
                    "alert": message,
                    "sound": "default",
                    "badge": 1,
                    "category": "YOUR_CUSTOM_CATEGORY",
                    "content-available": 1
                },
                "biometrix": payload
            })
        }
        try:
            _sns_client.publish(TargetArn=self.push_notifications_endpoint, Message=json.dumps(payload), MessageStructure='json')
        except ClientError as e:
            if 'EndpointDisabled' in str(e):
                raise UnauthorizedException(f'Endpoint disabled for device {self.id}')
            else:
                raise e

    def create_key(self):
        certificate_response = _iot_client.create_keys_and_certificate(setAsActive=True)

        _iot_client.attach_thing_principal(
            thingName=self.id,
            principal=certificate_response['certificateArn']
        )

        _iot_client.add_thing_to_thing_group(
            thingGroupName=f'users-{Config.get("ENVIRONMENT")}-device',
            thingName=self.id,
        )

        _iot_client.attach_principal_policy(
            policyName=Config.get('IOT_POLICY_NAME'),
            principal=certificate_response['certificateArn']
        )

        return (
            certificate_response['certificateId'],
            certificate_response['certificatePem'],
            certificate_response['keyPair']['PublicKey'],
            certificate_response['keyPair']['PrivateKey']
        )

    def _get_or_create_thing(self, device_type, owner_id):
        try:
            return _iot_client.describe_thing(thingName=self.id)['attributes']
        except ClientError as e:
            if 'ResourceNotFound' in str(e):
                print(f'Creating thing {self.id} with device_type={device_type}, owner_id={owner_id}')
                attributes = {
                    'device_type': device_type,
                    'owner_id': owner_id,
                }
                _iot_client.create_thing(
                    thingName=self.id,
                    thingTypeName=f'users-{Config.get("ENVIRONMENT")}-device',
                    attributePayload={'attributes': attributes}
                )
                return attributes
            else:
                raise

    def _delete_push_notification_settings(self):
        device_attributes = _iot_client.describe_thing(thingName=self.id)['attributes']
        if self._get_existing_push_notification_endpoint(device_attributes) is not None:
            _sns_client.delete_endpoint(EndpointArn=self._get_existing_push_notification_endpoint(device_attributes))
            _iot_client.update_thing(
                thingName=self.id,
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

    def _update_push_notification_settings(self, device_type, token, old_endpoint_arn=None, enabled=True, owner_id=None):
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
            _sns_client.delete_endpoint(EndpointArn=old_endpoint_arn)

        res = _sns_client.create_platform_endpoint(
            PlatformApplicationArn=application_arn,
            Token=token,
            Attributes=attributes,
            CustomUserData=json.dumps(custom_user_data)
        )

        _iot_client.update_thing(
            thingName=self.id,
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

    @staticmethod
    def _get_existing_push_notification_endpoint(attributes):
        if 'push_notifications.endpoint' in attributes:
            return attributes['push_notifications.endpoint']
        elif 'push_notifications_endpoint' in attributes:
            return attributes['push_notifications_endpoint']
        return None
