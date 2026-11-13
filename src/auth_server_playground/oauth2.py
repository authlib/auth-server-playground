import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge

from .models import AuthorizationCode
from .models import Client
from .models import Token
from .models import db
from .personas import find_by_username


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.payload.data.get("code_challenge")
        code_challenge_method = request.payload.data.get("code_challenge_method")
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.scope,
            persona_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return authorization_code.persona


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        # The playground does not check passwords.
        return find_by_username(username)


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return credential.persona

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.commit()


def save_token(token, request):
    persona_id = request.user.id if request.user else None
    db.session.add(
        Token(client_id=request.client.client_id, persona_id=persona_id, **token)
    )
    db.session.commit()


query_client = create_query_client_func(db.session, Client)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
authorization.register_grant(grants.ImplicitGrant)
authorization.register_grant(grants.ClientCredentialsGrant)
authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge()])
authorization.register_grant(PasswordGrant)
authorization.register_grant(RefreshTokenGrant)
authorization.register_endpoint(create_revocation_endpoint(db.session, Token))

require_oauth = ResourceProtector()
require_oauth.register_token_validator(
    create_bearer_token_validator(db.session, Token)()
)


def config_oauth(app):
    authorization.init_app(app)
