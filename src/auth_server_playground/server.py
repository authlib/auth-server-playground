"""The Authlib authorization server, built from the configuration document."""

import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from flask import current_app

from .models import AuthorizationCode
from .models import Client
from .models import Token
from .models import db
from .personas import find_by_username
from .store import settings_row

CACHE_KEY = "auth_server_playground.server"


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.scope,
            persona_id=request.user.id,
            code_challenge=request.payload.data.get("code_challenge"),
            code_challenge_method=request.payload.data.get("code_challenge_method"),
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
        # Without rotation, no new refresh token is issued: the old one stays valid.
        if self.INCLUDE_NEW_REFRESH_TOKEN:
            credential.refresh_token_revoked_at = now
        db.session.commit()


class PlaygroundCodeChallenge(CodeChallenge):
    def __init__(self, methods, required_for):
        super().__init__()
        # Authlib reads the supported methods from an attribute, not from the
        # server metadata.
        self.SUPPORTED_CODE_CHALLENGE_METHOD = list(methods)
        self.required_for = required_for

    def is_code_challenge_required(self, request):
        if self.required_for == "all":
            return True
        return super().is_code_challenge_required(request)


GRANTS = {
    "authorization_code": AuthorizationCodeGrant,
    "implicit": grants.ImplicitGrant,
    "password": PasswordGrant,
    "client_credentials": grants.ClientCredentialsGrant,
    "refresh_token": RefreshTokenGrant,
}


def save_token(token, request):
    persona_id = request.user.id if request.user else None
    db.session.add(
        Token(client_id=request.client.client_id, persona_id=persona_id, **token)
    )
    db.session.commit()


def configured(cls, **attributes):
    """Return a subclass of cls with the given class attributes.

    Authlib grants and endpoints read their client authentication methods
    from class attributes, not from the server metadata. Each build makes
    its own classes.
    """
    return type(cls.__name__, (cls,), attributes)


def build_server(document):
    """Build an authorization server that follows the configuration document."""
    metadata = document["metadata"]
    settings = document["settings"]
    grant_types = metadata["grant_types_supported"]
    auth_methods = metadata["token_endpoint_auth_methods_supported"]
    pkce_methods = metadata["code_challenge_methods_supported"]

    server = AuthorizationServer(
        query_client=create_query_client_func(db.session, Client),
        save_token=save_token,
    )
    server.load_config(
        {
            "OAUTH2_SCOPES_SUPPORTED": metadata["scopes_supported"],
            "OAUTH2_REFRESH_TOKEN_GENERATOR": "refresh_token" in grant_types,
            "OAUTH2_TOKEN_EXPIRES_IN": {
                grant_type: settings["access_token_lifetime"]
                for grant_type in grant_types
            },
        }
    )

    for grant_type in grant_types:
        attributes = {}
        if grant_type != "implicit":
            attributes["TOKEN_ENDPOINT_AUTH_METHODS"] = [
                method
                for method in auth_methods
                # Only confidential clients use this grant (RFC 6749 §4.4).
                if grant_type != "client_credentials" or method != "none"
            ]
        if grant_type == "refresh_token":
            attributes["INCLUDE_NEW_REFRESH_TOKEN"] = settings["refresh_token_rotation"]
        extensions = []
        if grant_type == "authorization_code" and pkce_methods:
            extensions.append(
                PlaygroundCodeChallenge(pkce_methods, settings["pkce_required"])
            )
        server.register_grant(configured(GRANTS[grant_type], **attributes), extensions)

    if settings["revocation_enabled"]:
        endpoint = create_revocation_endpoint(db.session, Token)
        server.register_endpoint(
            configured(endpoint, CLIENT_AUTH_METHODS=list(auth_methods))
        )
    return server


def get_server():
    """Return the server of the current configuration.

    The server is rebuilt when the revision of the settings changes. Two
    threads may rebuild it at the same time. They build the same server, so
    the last one wins.
    """
    row = settings_row()
    cached = current_app.extensions.get(CACHE_KEY)
    if cached is None or cached[0] != row.revision:
        cached = (row.revision, build_server(row.document))
        current_app.extensions[CACHE_KEY] = cached
    return cached[1]


require_oauth = ResourceProtector()
require_oauth.register_token_validator(
    create_bearer_token_validator(db.session, Token)()
)
