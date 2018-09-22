from flask import request
from werkzeug.routing import BaseConverter, ValidationError
from functools import wraps
import boto3
import json
import os
from exceptions import UnauthorizedException, InvalidSchemaException


def authentication_required(decorated_function):
    """Decorator to require a JWT token to be passed."""
    @wraps(decorated_function)
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers or not authenticate_user_jwt(request.headers['Authorization']):
            raise UnauthorizedException("Unauthorized")
        return decorated_function(*args, **kwargs)
    return wrapper


def self_authentication_required(decorated_function):
    """Decorator to require a JWT token to be passed."""
    @wraps(decorated_function)
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            raise UnauthorizedException("Unauthorized")
        principal_id = authenticate_user_jwt(request.headers['Authorization'])
        if len(args) == 0 or args[0] is None or args[0] != principal_id:
            raise UnauthorizedException("You may only execute this action on yourself")
        return decorated_function(*args, **kwargs)
    return wrapper


def authenticate_user_jwt(jwt):
    res = json.loads(boto3.client('lambda').invoke(
        FunctionName='users-{ENVIRONMENT}-apigateway-validateauth'.format(**os.environ),
        Payload=json.dumps({"authorizationToken": jwt}),
    )['Payload'].read())
    print(res)

    if 'principalId' in res:
        # Success
        return res['principalId']
    elif 'errorMessage' in res:
        # Some failure
        raise UnauthorizedException()


def body_required(required_body):
    def validate_request():
        if request.json is None or not isinstance(request.json, dict):
            t = type(request.json)
            raise InvalidSchemaException(f'Request body must be a JSON object, not "{t}"')
        validate_dict(request.json, required_body)

    def validate_dict(body, schema, prefix=''):
        if not isinstance(body, dict):
            raise InvalidSchemaException(f"Property '{prefix}' must be a dictionary")

        if prefix != '':
            prefix += '.'

        for key, key_schema in schema.items():
            value = body.get(key, None)
            if value is None:
                if isinstance(key_schema, (tuple, list)) and None in key_schema:
                    # Absence of key is allowed
                    continue
                elif key in body:
                    raise InvalidSchemaException(f"Property '{prefix}{key}' cannot be null")
                else:
                    raise InvalidSchemaException(f"Property '{prefix}{key}' is required")

            if isinstance(key_schema, (tuple, list)):
                key_schema = tuple(filter(None, key_schema))
                if len(key_schema) == 1:
                    key_schema = key_schema[0]

            if isinstance(key_schema, dict):
                validate_dict(body[key], key_schema, prefix=f'{prefix}{key}')

            # TODO basic type validation
            elif isinstance(key_schema, (str, int, float, bool)):
                pass

            elif issubclass(key_schema, BaseConverter):
                # Validate
                try:
                    key_schema.to_python(None, value)
                except ValidationError:
                    type_name = getattr(key_schema, 'type_name', key_schema.__name__)
                    raise InvalidSchemaException(f"Property '{prefix}{key}' must be of type '{type_name}'")

            else:
                pass

    def wrap(original_function):
        @wraps(original_function)
        def wrapped_function(*args, **kwargs):
            validate_request()
            return original_function(*args, **kwargs)

        return wrapped_function
    return wrap
