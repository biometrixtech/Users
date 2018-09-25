from aws_xray_sdk.core import xray_recorder

from ._transport import invoke_lambda_sync, invoke_apigateway_sync


class Service:
    def __init__(self, name, version):
        self.name = name
        self.version = version

    @xray_recorder.capture('fathomapi.comms.service.call_apigateway_sync')
    def call_apigateway_sync(self, method, endpoint, body=None, headers=None):
        if headers is None:
            headers = {}
        headers.update({'Authorization': _get_service_token()})

        return invoke_apigateway_sync(self.name, self.version, method, endpoint, body, headers)

    def call_lambda_sync(self, function_name, payload=None):
        return invoke_lambda_sync(f'{self.name}-{{ENVIRONMENT}}-{function_name}', self.version, payload)


@xray_recorder.capture('fathomapi.comms.service._get_service_token')
def _get_service_token():
    return invoke_lambda_sync('users-{ENVIRONMENT}-apigateway-serviceauth', '1_0')['token']
