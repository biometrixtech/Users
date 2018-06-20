import json
import uuid
from flask_lambda import FlaskLambda
from flask_bcrypt import Bcrypt
from flask import Response, jsonify
from serialisable import json_serialise
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
        if validate_uuid4(value):
            return value
        raise ValidationError()

    def to_url(self, value):
        return value


def validate_uuid4(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        # If the uuid_string is a valid hex code, but an invalid uuid4, the UUID.__init__
        # will convert it to a valid uuid4. This is bad for validation purposes.
        return val.hex == uuid_string.replace('-', '')
    except ValueError:
        # If it's a value error, then the string is not a valid hex code for a UUID.
        return False


app = FlaskLambda(__name__)
app.response_class = ApiResponse
app.url_map.strict_slashes = False
app.url_map.converters['uuid'] = UuidConverter
bcrypt = Bcrypt(app)


