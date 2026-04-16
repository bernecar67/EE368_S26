import os
import time

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import create_query_client_func, create_save_token_func
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator

from models import Client, AuthorizationCode, db, User, Token


class MyAuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        auth_code = AuthorizationCode()
        auth_code.code = code
        auth_code.client_id = request.client.get_client_id()
        auth_code.user_id = request.user.id
        auth_code.redirect_uri = request.redirect_uri
        auth_code.response_type = request.response_type
        auth_code.scope = request.scope
        auth_code.nonce = request.data.get('nonce')
        auth_code.auth_time = time.time()

        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(code=code, client_id=client.get_client_id()).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        # Retrieve the token from the database
        return Token.query.filter_by(access_token=token_string).first()


# Allow insecure transport (http instead of https) for development purposes only
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

auth_server = AuthorizationServer()
require_oauth = ResourceProtector()

def configure_oauth(app):
    auth_server.init_app(
        app,
        query_client=create_query_client_func(db.session, Client),
        save_token=create_save_token_func(db.session, Token)
    )
    auth_server.register_grant(MyAuthorizationCodeGrant)
    auth_server.register_token_generator('default', auth_server.create_bearer_token_generator(app.config))

    # protect resource
    require_oauth.register_token_validator(MyBearerTokenValidator())
