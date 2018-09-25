from aws_xray_sdk.core import xray_recorder
import boto3
import json
import os


@xray_recorder.capture('apigateway.query_postgres')
def query_postgres(query, parameters):
    lambda_client = boto3.client('lambda')
    res = json.loads(lambda_client.invoke(
        FunctionName='infrastructure-{ENVIRONMENT}-querypostgres'.format(**os.environ),
        Payload=json.dumps({
            "Queries": [{"Query": query, "Parameters": parameters}],
            "Config": {"ENVIRONMENT": os.environ['ENVIRONMENT']}
        }),
    )['Payload'].read().decode('utf-8'))
    if len(list(filter(None, res['Errors']))):
        raise Exception(list(filter(None, res['Errors'])))
    else:
        return res['Results'][0]
