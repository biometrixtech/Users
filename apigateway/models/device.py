from botocore.exceptions import ClientError
import boto3
import json
import os

from ._iot_entity import IotEntity
from exceptions import NoSuchEntityException, UnauthorizedException

sns_client = boto3.client('sns')


class Device(IotEntity):

    @staticmethod
    def schema():
        with open('schemas/device.json', 'r') as f:
            return json.load(f)
        
    @property
    def thing_type(self):
        return os.environ['DEVICES_THING_TYPE']

    @property
    def push_notifications_endpoint(self):
        print(self.get())
        return self.get()['push_notifications']['endpoint']

    @property
    def push_notifications_enabled(self):
        return self.get()['push_notifications']['enabled']

    def send_push_notification(self, message):

        if self.push_notifications_endpoint is None:
            raise NoSuchEntityException(f'No push notification endpoint configured for device {self.id}')

        if not self.push_notifications_enabled:
            raise UnauthorizedException(f'Push notifications disabled for device {self.id}')

        print('Sending notification to endpoint {}'.format(self.push_notifications_endpoint))
        payload = {
            'default': 'Your plan is ready!',
            'GCM': {
                "data": {
                    "message": message,
                    "biometrix": {
                        "hello": "world",
                        "theanswer": 42,
                    }
                },
                "time_to_live": 3600,
                "collapse_key": "YOUR_CUSTOM_CATEGORY"
            },
            "APNS": {
                "aps": {
                    "alert": message,
                    "sound": "default",
                    "badge": 1,
                    "category": "YOUR_CUSTOM_CATEGORY",
                    "content-available": 1
                },
                "biometrix": {
                    "hello": "world",
                    "theanswer": 42,
                }
            }
        }
        try:
            sns_client.publish(TargetArn=self.push_notifications_endpoint, Message=json.dumps(payload), MessageStructure='json')
        except ClientError as e:
            if 'EndpointDisabled' in str(e):
                raise UnauthorizedException(f'Endpoint disabled for device {self.id}')
            else:
                raise e
