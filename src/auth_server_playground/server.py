"""The Authlib authorization server, built from the configuration document."""

import time

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2.rfc6749 import InvalidClientError
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9101 import JWTAuthenticationRequest
from authlib.oidc.core import ClaimsParameter
from authlib.oidc.core import OpenIDCode
from authlib.oidc.core import UserInfoEndpoint
from authlib.oidc.prompt_create import PromptValues
from flask import current_app
from flask import url_for
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.errors import UnsupportedAlgorithmError
from sqlalchemy.exc import IntegrityError

from .client_keys import ClientKeysError
from .client_keys import public_keys
from .client_keys import secret_key
from .keys import active_kid
from .keys import private_key_set
from .metadata import issuer_for
from .models import AuthorizationCode
from .models import Client
from .models import ClientAssertion
from .models import Token
from .models import db
from .personas import find_by_username
from .personas import user_info
from .registration import ConfigurationEndpoint
from .registration import RegistrationEndpoint
from .settings import HMAC_ALGORITHMS
from .settings import JWT_AUTH_METHODS
from .settings import is_oidc_enabled
from .snapshot import MAX_TIMESTAMP
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
            nonce=request.payload.data.get("nonce"),
            # Only the OpenIDCode extension sets them.
            auth_time=getattr(request, "auth_time", None),
            acr=getattr(request, "acr", None),
            # Only the ClaimsParameter extension sets it.
            claims_request=getattr(request, "claims_request", None),
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

    def revoke_authorization_code_tokens(self, code, client):
        """Revoke every token based on the code (RFC 6749 §4.1.2)."""
        now = int(time.time())
        Token.query.filter_by(authorization_code=code).update(
            {"access_token_revoked_at": now, "refresh_token_revoked_at": now}
        )
        db.session.commit()


class PlaygroundOpenIDCode(OpenIDCode):
    def __init__(self, issuer, id_token_lifetime):
        super().__init__(require_nonce=False)
        self.issuer = issuer
        # Authlib computes iat and exp from one clock reading.
        self.DEFAULT_EXPIRES_IN = id_token_lifetime

    def exists_nonce(self, nonce, request):
        return (
            AuthorizationCode.query.filter_by(
                client_id=request.payload.client_id, nonce=nonce
            ).first()
            is not None
        )

    def get_client_claims(self, client):
        return {"iss": issuer_for(self.issuer)}

    def resolve_client_private_key(self, client):
        return private_key_set()

    def get_encode_header(self, client):
        # Authlib has no separate hook for the keys that verify id_token_hint.
        # So resolve_client_private_key returns the retired keys too, and joserfc
        # would sign with a random key of the algorithm. The kid picks the active key.
        alg = self.get_client_algorithm(client)
        header = {"alg": alg}
        if kid := active_kid(alg):
            header["kid"] = kid

        return header

    def generate_user_info(self, user, scope, claims):
        return user_info(user, scope, claims)


class PlaygroundUserInfoEndpoint(UserInfoEndpoint):
    def generate_user_info(self, user, scope, claims):
        return user_info(user, scope, claims)

    def get_token_claims_request(self, token):
        return token.claims_request


class PlaygroundJWTAuthenticationRequest(JWTAuthenticationRequest):
    """Accept signed and unsigned request objects."""

    def __init__(
        self,
        issuer,
        algorithms,
        require_signed,
        allow_private_addresses,
        support_request,
    ):
        # Per RFC 9101 §10.4, fetching a request_uri exposes the server to SSRF.
        super().__init__(support_request=support_request, support_request_uri=False)
        self.issuer = issuer
        self.algorithms = algorithms
        self.require_signed = require_signed
        self.allow_private_addresses = allow_private_addresses

    def resolve_client_public_key(self, client):
        # Authlib asks for the key before it reads the alg, even for alg none.
        # joserfc calls resolve with the token.
        # It does not call it for alg none, so an unsigned object fetches nothing.
        def resolve(token):
            if token.headers()["alg"] in HMAC_ALGORITHMS:
                return secret_key(client)

            return public_keys(
                client, allow_private_addresses=self.allow_private_addresses
            )

        return resolve

    def get_request_object_signing_algorithms(self, client):
        # Per OIDC Registration §2, a client algorithm applies to all its
        # request objects.
        alg = client.client_metadata.get("request_object_signing_alg")
        wanted = [alg] if alg else self.algorithms
        return [candidate for candidate in wanted if candidate in self.algorithms]

    def get_client_require_signed_request_object(self, client):
        return bool(client.client_metadata.get("require_signed_request_object"))

    def get_server_metadata(self):
        return {
            "issuer": issuer_for(self.issuer),
            "request_object_signing_alg_values_supported": self.algorithms,
            "require_signed_request_object": self.require_signed,
        }


class PlaygroundPromptValues(PromptValues):
    """Refuse the prompt values that the configuration does not list."""

    def __init__(self, values):
        self.values = list(values)

    def get_server_metadata(self):
        return {"prompt_values_supported": self.values}


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


class PlaygroundClientAssertion(JWTBearerClientAssertion):
    """private_key_jwt or client_secret_jwt (RFC 7523 §2.2, OIDC Core §9)."""

    def __init__(self, method, algorithms, issuer, allow_private_addresses):
        super().__init__()
        self.CLIENT_AUTH_METHOD = method
        self.algorithms = [alg for alg in algorithms if alg in JWT_AUTH_METHODS[method]]
        self.issuer = issuer
        self.allow_private_addresses = allow_private_addresses

    def __call__(self, query_client, request):
        # The Authlib dispatcher stops at the first exception, and
        # JWTBearerClientAssertion raises one for a client of the other
        # method. So each instance leaves these clients to the other one,
        # before the jti is used.
        method = self.claimed_method(query_client, request)
        if method is not None and method != self.CLIENT_AUTH_METHOD:
            return None

        return super().__call__(query_client, request)

    def claimed_method(self, query_client, request):
        """Return the method of the client in the assertion, if it exists."""
        assertion = request.form.get("client_assertion")
        if (
            request.form.get("client_assertion_type") != self.CLIENT_ASSERTION_TYPE
            or not assertion
        ):
            return None

        try:
            _, claims = self.extract_assertion(assertion)
        except InvalidClientError:
            return None

        client_id = claims.get("sub")
        client = query_client(client_id) if isinstance(client_id, str) else None
        return client.token_endpoint_auth_method if client else None

    def get_audiences(self):
        return [issuer_for(self.issuer), url_for("oauth.issue_token", _external=True)]

    def resolve_client_public_key(self, client):
        # Authlib calls jwt.decode without algorithms, and joserfc then
        # accepts HS256, RS256 and ES256 only, whatever the server publishes.
        # So process_assertion_claims passes the algorithms itself. An empty
        # list must be refused here: joserfc would take it as "use the
        # defaults". It also avoids fetching the jwks_uri for nothing.
        if not self.algorithms:
            raise InvalidClientError(
                description=f"The server has no algorithm for {self.CLIENT_AUTH_METHOD}."
            )

        try:
            if self.CLIENT_AUTH_METHOD == "client_secret_jwt":
                key = secret_key(client)
            else:
                key = public_keys(
                    client, allow_private_addresses=self.allow_private_addresses
                )
        except ClientKeysError as error:
            raise InvalidClientError(description=error.description) from error

        required = client.client_metadata.get("token_endpoint_auth_signing_alg")

        # Authlib ignores token_endpoint_auth_signing_alg of the client.
        def resolve(token):
            if required and token.headers()["alg"] != required:
                raise UnsupportedAlgorithmError(f"The client signs with {required}.")

            return key

        return resolve

    def process_assertion_claims(self, assertion, resolve_key):
        try:
            token = jwt.decode(assertion, resolve_key, algorithms=self.algorithms)
        except JoseError as error:
            raise InvalidClientError(description=error.description) from error

        self.verify_claims(token.claims)
        return token.claims

    def validate_jti(self, claims, jti):
        # A huge exp would overflow the integer column.
        if not 0 <= claims["exp"] <= MAX_TIMESTAMP:
            raise InvalidClientError(description="Invalid claim: 'exp'")

        db.session.add(
            ClientAssertion(
                client_id=claims["sub"], jti=str(jti), expires_at=int(claims["exp"])
            )
        )
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return False

        return True


GRANTS = {
    "authorization_code": AuthorizationCodeGrant,
    "implicit": grants.ImplicitGrant,
    "password": PasswordGrant,
    "client_credentials": grants.ClientCredentialsGrant,
    "refresh_token": RefreshTokenGrant,
}


def code_of(request):
    """Return the authorization code that the new token comes from, if any."""
    if authorization_code := getattr(request, "authorization_code", None):
        return authorization_code.code

    # A refreshed token keeps the code of the token it replaces.
    if refresh_token := getattr(request, "refresh_token", None):
        return refresh_token.authorization_code

    return None


def claims_request_of(request):
    """Return the claims parameter of the request behind the new token, if any."""
    if authorization_code := getattr(request, "authorization_code", None):
        return authorization_code.claims_request

    # A refreshed token keeps the claims request of the token it replaces.
    if refresh_token := getattr(request, "refresh_token", None):
        return refresh_token.claims_request

    return None


def token_saver(refresh_token_lifetime):
    """Return a save_token function that sets the expiration of refresh tokens."""

    def save_token(token, request):
        now = int(time.time())
        item = Token(
            client_id=request.client.client_id,
            persona_id=request.user.id if request.user else None,
            authorization_code=code_of(request),
            claims_request=claims_request_of(request),
            **{**token, "issued_at": now},
        )
        if item.refresh_token:
            item.refresh_token_expires_at = now + refresh_token_lifetime

        db.session.add(item)
        db.session.commit()

    return save_token


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
        save_token=token_saver(settings["refresh_token_lifetime"]),
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

        if grant_type == "authorization_code" and is_oidc_enabled(document):
            extensions.append(
                PlaygroundOpenIDCode(metadata["issuer"], settings["id_token_lifetime"])
            )

        server.register_grant(configured(GRANTS[grant_type], **attributes), extensions)

    revocation_methods = metadata["revocation_endpoint_auth_methods_supported"]
    jwt_methods = set(auth_methods)
    if settings["revocation_enabled"]:
        jwt_methods |= set(revocation_methods)

    for method in JWT_AUTH_METHODS:
        if method not in jwt_methods:
            continue

        server.register_client_auth_method(
            method,
            PlaygroundClientAssertion(
                method,
                metadata["token_endpoint_auth_signing_alg_values_supported"],
                metadata["issuer"],
                settings["outbound_private_addresses"],
            ),
        )

    if settings["revocation_enabled"]:
        endpoint = create_revocation_endpoint(db.session, Token)
        server.register_endpoint(
            configured(endpoint, CLIENT_AUTH_METHODS=list(revocation_methods))
        )

    if is_oidc_enabled(document):
        server.register_endpoint(
            PlaygroundUserInfoEndpoint(resource_protector=require_oauth)
        )
        if metadata["claims_parameter_supported"]:
            server.register_extension(ClaimsParameter())

        server.register_extension(
            PlaygroundPromptValues(metadata["prompt_values_supported"])
        )
        server.register_extension(
            PlaygroundJWTAuthenticationRequest(
                metadata["issuer"],
                metadata["request_object_signing_alg_values_supported"],
                metadata["require_signed_request_object"],
                settings["outbound_private_addresses"],
                metadata["request_parameter_supported"],
            )
        )

    registration = settings["registration"]
    if registration != "disabled":
        oidc = is_oidc_enabled(document)
        server.register_endpoint(
            RegistrationEndpoint(registration, settings["initial_access_token"], oidc)
        )
        server.register_endpoint(ConfigurationEndpoint(oidc))

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
