from aws_xray_sdk.core import xray_recorder
import boto3
import json
import requests
import os

_lambda_client = boto3.client('lambda')


@xray_recorder.capture('fathomapi.comms._transport.invoke_lambda_sync')
def invoke_lambda_sync(function_name, version, payload=None):
    """
    Invoke a lambda function synchronously
    :param str function_name: The lambda function name or ARN to call.  Environment variables will be interpolated.
    :param str version: The version of the function to call
    :param dict payload: The payload to call with
    :return: dict
    """
    res = _lambda_client.invoke(
        FunctionName=f'{function_name}:{version}'.format(**os.environ),
        Payload=json.dumps(payload or {}),
    )
    return json.loads(res['Payload'].read().decode('utf-8'))


@xray_recorder.capture('fathomapi.comms._transport.invoke_apigateway_sync')
def invoke_apigateway_sync(service, version, method, endpoint, body=None, headers=None):
    """
    Make an HTTP request to an API Gateway endpoint synchronously
    :param str service:
    :param str version:
    :param str method: HTTP method
    :param str endpoint: Query path
    :param dict body:
    :param dict headers:
    :return:
    """
    url = f"http://apis.{os.environ['ENVIRONMENT']}.fathomai.com/{service}/{version}/{endpoint}"

    all_headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Fathomai API {SERVICE}:{AWS_LAMBDA_FUNCTION_VERSION}'.format(**os.environ)
    }
    all_headers.update(headers or {})

    response = requests.request(method, url, data=json.dumps(body), headers=all_headers)

    # TODO validation
    return response.json()
