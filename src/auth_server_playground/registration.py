"""Dynamic client registration (RFC 7591) and client configuration (RFC 7592)."""

import hmac
import secrets

from authlib.oauth2.rfc7591 import ClientMetadataClaims
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from authlib.oauth2.rfc7591 import InvalidClientMetadataError
from authlib.oauth2.rfc7592 import ClientConfigurationEndpoint
from authlib.oauth2.rfc9101 import ClientMetadataClaims as RequestObjectClaims
from authlib.oidc.registration import ClientMetadataClaims as OIDCClientMetadataClaims
from flask import request as flask_request
from flask import url_for

from .client_keys import client_key_errors
from .metadata import current_metadata
from .models import Client
from .models import db
from .settings import SECRET_AUTH_METHODS
from .snapshot import UNSUPPORTED_CLIENT_METADATA
from .store import delete_client

#: The defaults of RFC 7591 §2. Authlib does not store them. It does not check
#: them against the server metadata either: its hooks only run for the keys
#: that the client sends.
DEFAULT_METADATA = {"grant_types": ["authorization_code"], "response_types": ["code"]}


def claims_classes(oidc):
    if oidc:
        return [ClientMetadataClaims, OIDCClientMetadataClaims, RequestObjectClaims]

    return [ClientMetadataClaims]


def bearer_token(request):
    """Return the Bearer token of the Authorization header, or None."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None

    return token


def checked_metadata(metadata):
    """Add the RFC 7591 defaults, and apply the rules that Authlib does not apply."""
    metadata = {**DEFAULT_METADATA, **metadata}
    if unsupported := [key for key in UNSUPPORTED_CLIENT_METADATA if key in metadata]:
        raise InvalidClientMetadataError(
            f"The server does not support {', '.join(unsupported)}."
        )

    if errors := client_key_errors(metadata):
        raise InvalidClientMetadataError(" ".join(errors.values()))

    return metadata


def registration_info(client):
    return {
        "registration_client_uri": url_for(
            "oauth.client_configuration", client_id=client.client_id, _external=True
        ),
        "registration_access_token": client.registration_access_token,
    }


class RegistrationEndpoint(ClientRegistrationEndpoint):
    def __init__(self, mode, initial_access_token, oidc):
        super().__init__(claims_classes=claims_classes(oidc))
        self.mode = mode
        self.initial_access_token = initial_access_token

    def authenticate_token(self, request):
        if self.mode == "open":
            return True

        token = bearer_token(request)
        if token and hmac.compare_digest(
            token.encode(), self.initial_access_token.encode()
        ):
            return True

        return None

    def extract_client_metadata(self, request):
        metadata = checked_metadata(super().extract_client_metadata(request))
        # Authlib does not pass the metadata to generate_client_secret.
        request.client_metadata = metadata
        return metadata

    def generate_client_id(self, request):
        return secrets.token_urlsafe(18)

    def generate_client_secret(self, request):
        method = request.client_metadata["token_endpoint_auth_method"]
        if method not in SECRET_AUTH_METHODS:
            return None

        return secrets.token_urlsafe(36)

    def generate_client_info(self, request):
        info = super().generate_client_info(request)
        # Per RFC 7591 §3.2.1, client_secret_expires_at goes with a client_secret.
        # Authlib sends both, with a null secret. Authlib main fixes it (PR #1071).
        if info["client_secret"] is None:
            del info["client_secret"]
            del info["client_secret_expires_at"]

        return info

    def get_server_metadata(self):
        return current_metadata()

    def save_client(self, client_info, client_metadata, request):
        client = Client(
            client_id=client_info["client_id"],
            client_secret=client_info.get("client_secret", ""),
            client_id_issued_at=client_info["client_id_issued_at"],
            client_secret_expires_at=client_info.get("client_secret_expires_at", 0),
            registration_access_token=secrets.token_urlsafe(32),
        )
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        return client

    def generate_client_registration_info(self, client, request):
        return registration_info(client)


class RegistrationToken:
    """The registration access token of a client (RFC 7592 §1)."""

    def __init__(self, client):
        self.client = client

    def check_client(self, client):
        return client.client_id == self.client.client_id


class ConfigurationEndpoint(ClientConfigurationEndpoint):
    def __init__(self, oidc):
        super().__init__(claims_classes=claims_classes(oidc))

    def authenticate_token(self, request):
        token = bearer_token(request)
        if token is None:
            return None

        client = Client.query.filter_by(registration_access_token=token).first()
        return RegistrationToken(client) if client else None

    def authenticate_client(self, request):
        return Client.query.filter(
            Client.client_id == flask_request.view_args["client_id"],
            Client.registration_access_token.is_not(None),
        ).first()

    def revoke_access_token(self, token, request):
        """Per RFC 7592 §2, the server SHOULD revoke the token.

        The playground keeps it: the token belongs to another client, which still exists.
        """

    def check_permission(self, client, request):
        return True

    def extract_client_metadata(self, request):
        return checked_metadata(super().extract_client_metadata(request))

    def introspect_client(self, client):
        info = super().introspect_client(client)
        # The client mixin returns an empty secret for a public client.
        if not client.client_secret:
            info.pop("client_secret", None)

        return info

    def update_client(self, client, client_metadata, request):
        client.set_client_metadata(client_metadata)
        client.update_secret()
        db.session.commit()
        return client

    def delete_client(self, client, request):
        delete_client(client)

    def generate_client_registration_info(self, client, request):
        return registration_info(client)

    def get_server_metadata(self):
        return current_metadata()
