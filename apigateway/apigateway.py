import json
import sys
import traceback

from exceptions import ApplicationException
from flask import Response, jsonify
from flask_lambda import FlaskLambda
from serialisable import json_serialise

from aws_xray_sdk.core import patch_all
patch_all()


class ApiResponse(Response):
    @classmethod
    def force_type(cls, rv, environ=None):
        if isinstance(rv, dict):
            # Round-trip through our JSON serialiser to make it parseable by AWS's
            rv = json.loads(json.dumps(rv, sort_keys=True, default=json_serialise))
            rv = jsonify(rv)
        return super().force_type(rv, environ)


app = FlaskLambda(__name__)
app.response_class = ApiResponse
app.url_map.strict_slashes = False

from routes.user import app as user_routes
app.register_blueprint(user_routes, url_prefix='/v1/user')
app.register_blueprint(user_routes, url_prefix='/users/user')


@app.errorhandler(500)
def handle_server_error(e):
    tb = sys.exc_info()[2]
    return {'message': str(e.with_traceback(tb))}, 500, {'Status': type(e).__name__}


@app.errorhandler(404)
def handle_unrecognised_endpoint(_):
    return {"message": "You must specify an endpoint"}, 404, {'Status': 'UnrecognisedEndpoint'}


@app.errorhandler(405)
def handle_unrecognised_method(_):
    return {"message": "The given method is not supported for this endpoint"}, 405, {'Status': 'UnsupportedMethod'}


@app.errorhandler(ApplicationException)
def handle_application_exception(e):
    traceback.print_exception(*sys.exc_info())
    return {'message': e.message}, e.status_code, {'Status': e.status_code_text}


def handler(event, context):
    print(json.dumps(event))

    # Trim trailing slashes from urls
    event['path'] = event['path'].rstrip('/')

    ret = app(event, context)
    ret['headers'].update({
        'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Origin': '*',
    })

    # Unserialise JSON output so AWS can immediately serialise it again...
    ret['body'] = ret['body'].decode('utf-8')

    if ret['headers']['Content-Type'] == 'application/octet-stream':
        ret['isBase64Encoded'] = True

    print(json.dumps(ret))
    return ret


if __name__ == '__main__':
    app.run(debug=True)
