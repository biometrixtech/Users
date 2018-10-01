from fathomapi.api.handler import handler as fathom_handler
from fathomapi.api.flask_app import app

from routes.account import account_app as account_routes
from routes.user import user_app as user_routes
from routes.device import device_app as device_routes
from routes.misc import misc_app as misc_routes
app.register_blueprint(account_routes, url_prefix='/account')
app.register_blueprint(user_routes, url_prefix='/user')
app.register_blueprint(device_routes, url_prefix='/device')
app.register_blueprint(misc_routes, url_prefix='/misc')


def handler(event, context):
    return fathom_handler(event, context)


if __name__ == '__main__':
    app.run(debug=True)
