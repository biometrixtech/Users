from flask import request
from flask_lambda import FlaskLambda
from serialisable import json_serialise
from uuid import UUID
import base64
import boto3
import datetime
import json
import os
import sys
import time
from exceptions import ApplicationException, NoSuchEntityException, InvalidSchemaException
from aws_xray_sdk.core import xray_recorder, patch_all

patch_all()
app = FlaskLambda(__name__)


@app.route('/v1/user/<user_id>', methods=['GET'])
@app.route('/users/user/<user_id>', methods=['GET'])
def handle_user_get(user_id):
    if not validate_uuid4(user_id):
        raise InvalidSchemaException('user_id must be a uuid')

    user_data, teams, training_groups = query_postgres([
        (
            """SELECT
                    id AS user_id,
                    role AS user_role,
                    organization_id AS organization_id,
                    created_at AS created_date,
                    updated_at AS updated_date
                FROM users WHERE id = %s""",
            [user_id]
        ),
        (
            """SELECT team_id FROM teams_users WHERE user_id = %s""",
            [user_id]
        ),
        (
            """SELECT training_group_id FROM training_groups_users WHERE user_id = %s""",
            [user_id]
        ),
    ])
    print(user_data, teams, training_groups)
    if len(user_data) == 0:
        raise NoSuchEntityException()

    user = {
        'user_id': user_data[0]['user_id'],
        'role': user_data[0]['user_role'],
        'created_date': datetime.datetime.strptime(user_data[0]['created_date'], "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ"),
        'updated_date': datetime.datetime.strptime(user_data[0]['updated_date'], "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ"),
        'team_id': teams[0]['team_id'] if len(teams) else None,
        'training_group_ids': [t['training_group_id'] for t in training_groups],
    }

    return json.dumps({'user': user}, default=json_serialise)


@xray_recorder.capture('apigateway.query_postgres')
def query_postgres(queries):
    lambda_client = boto3.client('lambda', region_name=os.environ['AWS_REGION'])
    res = json.loads(lambda_client.invoke(
        FunctionName='arn:aws:lambda:{AWS_REGION}:{AWS_ACCOUNT_ID}:function:infrastructure-{ENVIRONMENT}-querypostgres'.format(**os.environ),
        Payload=json.dumps({
            "Queries": [{"Query": query[0], "Parameters": query[1]} for query in queries],
            "Config": {"ENVIRONMENT": os.environ['ENVIRONMENT']}
        }),
    )['Payload'].read().decode('utf-8'))
    if len(list(filter(None, res['Errors']))):
        raise Exception(list(filter(None, res['Errors'])))
    else:
        return res['Results']


def validate_uuid4(uuid_string):
    try:
        val = UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False


@app.errorhandler(500)
def handle_server_error(e):
    tb = sys.exc_info()[2]
    return json.dumps({'message': str(e.with_traceback(tb))}, default=json_serialise), 500, {'Status': type(e).__name__}


@app.errorhandler(404)
def handle_unrecognised_endpoint(_):
    return '{"message": "You must specify an endpoint"}', 404, {'Status': 'UnrecognisedEndpoint'}


@app.errorhandler(405)
def handle_unrecognised_endpoint(_):
    return '{"message": "The method is not allowed for the requested URL."}', 405, {'Status': 'MethodNotSupported'}


@app.errorhandler(ApplicationException)
def handle_application_exception(e):
    print(e)
    return json.dumps({'message': e.message}, default=json_serialise), e.status_code, {'Status': e.status_code_text}


def handler(event, context):
    print(json.dumps(event))
    ret = app(event, context)
    ret['headers'].update({
        'Content-Type': 'application/json',
        'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Origin': '*',
    })
    # Round-trip through our JSON serialiser to make it parseable by AWS's
    print(ret)
    return json.loads(json.dumps(ret, sort_keys=True, default=json_serialise))


if __name__ == '__main__':
    app.run(debug=True)
