"""The keys of the clients, and the key rules that Authlib does not apply."""

import json

from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from .outbound import OutboundError
from .outbound import fetch
from .settings import JWT_AUTH_METHODS


class ClientKeysError(JoseError):
    """The keys of a client cannot be read.

    A JoseError, so that Authlib turns it into an invalid_request_object
    error when it decodes a request object.
    """

    error = "invalid_client_keys"


def public_keys(client, *, allow_private_addresses):
    """Return the key set of the client, from jwks or from jwks_uri."""
    if client.jwks_uri:
        try:
            data = json.loads(
                fetch(client.jwks_uri, allow_private_addresses=allow_private_addresses)
            )
        except OutboundError as error:
            raise ClientKeysError(f"jwks_uri: {error}") from error
        except ValueError as error:
            raise ClientKeysError("jwks_uri: the response is not JSON") from error
    else:
        data = client.client_metadata.get("jwks")
    if not data:
        raise ClientKeysError("The client has no keys.")
    try:
        return KeySet.import_key_set(data)
    except (JoseError, ValueError, KeyError, TypeError) as error:
        source = "jwks_uri" if client.jwks_uri else "jwks"
        raise ClientKeysError(f"{source}: the keys are not a JWK Set") from error


def secret_key(client):
    """Return the client secret as an HMAC key."""
    if not client.client_secret:
        raise ClientKeysError("The client has no secret.")
    return OctKey.import_key(client.client_secret)


def client_key_errors(metadata):
    """Return the key errors of client metadata, by metadata key.

    Authlib already checks that jwks and jwks_uri exclude each other, and
    that jwks holds public keys only.
    """
    errors = {}
    method = metadata.get("token_endpoint_auth_method", "client_secret_basic")
    if method == "private_key_jwt" and not (
        metadata.get("jwks") or metadata.get("jwks_uri")
    ):
        errors["jwks"] = "private_key_jwt needs jwks or jwks_uri."
    alg = metadata.get("token_endpoint_auth_signing_alg")
    algorithms = JWT_AUTH_METHODS.get(method)
    if alg and algorithms and alg not in algorithms:
        errors["token_endpoint_auth_signing_alg"] = (
            f"{method} uses {', '.join(algorithms)}."
        )
    return errors
