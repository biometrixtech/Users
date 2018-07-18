import json
from flask_lambda import FlaskLambda
from flask_bcrypt import Bcrypt
from flask import Response, jsonify
from serialisable import json_serialise
from utils import validate_uuid4
from werkzeug.routing import BaseConverter, ValidationError


class ApiResponse(Response):
    @classmethod
    def force_type(cls, rv, environ=None):
        if isinstance(rv, dict):
            # Round-trip through our JSON serialiser to make it parseable by AWS's
            rv = json.loads(json.dumps(rv, sort_keys=True, default=json_serialise))
            rv = jsonify(rv)
        return super().force_type(rv, environ)


class UuidConverter(BaseConverter):
    def to_python(self, value):
        if validate_uuid4(str(value)):
            return value
        raise ValidationError()

    def to_url(self, value):
        return value

    type_name = 'uuid'


app = FlaskLambda(__name__)
app.response_class = ApiResponse
app.url_map.strict_slashes = False
app.url_map.converters['uuid'] = UuidConverter
bcrypt = Bcrypt(app)


