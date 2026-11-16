"""The configuration document of the server.

This module does not touch the database. ``store.py`` reads and writes the
document.
"""

import copy

from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oidc.core import UserInfo
from authlib.oidc.discovery import OpenIDProviderMetadata

GRANT_TYPES = [
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token",
]
RESPONSE_TYPES = {"authorization_code": "code", "implicit": "token"}
AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
PKCE_METHODS = ["S256", "plain"]
PKCE_REQUIRED = ["all", "public"]
#: The asymmetric signing algorithms. RFC 9864 deprecates EdDSA for Ed25519.
ASYMMETRIC_ALGORITHMS = ["RS256", "PS256", "ES256", "Ed25519"]
ID_TOKEN_ALGORITHMS = ASYMMETRIC_ALGORITHMS
#: The algorithms that use the client secret as key.
HMAC_ALGORITHMS = ["HS256"]
#: The algorithms of the JWTs that clients sign: assertions and request objects.
CLIENT_JWT_ALGORITHMS = [*ASYMMETRIC_ALGORITHMS, *HMAC_ALGORITHMS]
REQUEST_OBJECT_ALGORITHMS = ["none", *CLIENT_JWT_ALGORITHMS]

REGISTRATION_MODES = ["disabled", "open", "token"]

#: The issuer used to validate a document whose issuer comes from requests.
DEFAULT_ISSUER = "http://localhost"

ENDPOINTS = [
    "authorization_endpoint",
    "token_endpoint",
    "revocation_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
]

#: The interface languages, published as ui_locales_supported.
UI_LOCALES = ["en", "fr"]
PROMPT_VALUES = ["none", "login", "consent", "select_account"]

#: The stored metadata that only OpenID Connect publishes.
OIDC_METADATA = (
    "id_token_signing_alg_values_supported",
    "request_object_signing_alg_values_supported",
    "require_signed_request_object",
)

#: The client authentication methods that sign a JWT.
JWT_AUTH_METHODS = {
    "private_key_jwt": ASYMMETRIC_ALGORITHMS,
    "client_secret_jwt": HMAC_ALGORITHMS,
}
#: The client authentication methods that need a client secret.
SECRET_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "client_secret_jwt"]

#: The longest token lifetime, so that expiration dates fit in the database.
MAX_LIFETIME = 365 * 24 * 3600

# Defaults per RFC 9700.
DEFAULT_DOCUMENT = {
    "metadata": {
        "issuer": None,
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "token_endpoint_auth_methods_supported": list(AUTH_METHODS),
        "token_endpoint_auth_signing_alg_values_supported": list(CLIENT_JWT_ALGORITHMS),
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "request_object_signing_alg_values_supported": list(REQUEST_OBJECT_ALGORITHMS),
        "require_signed_request_object": False,
    },
    "settings": {
        "pkce_required": "all",
        "revocation_enabled": True,
        "access_token_lifetime": 3600,
        "refresh_token_lifetime": 14 * 24 * 3600,
        "refresh_token_rotation": True,
        "id_token_lifetime": 3600,
        "registration": "open",
        "initial_access_token": None,
        "outbound_private_addresses": True,
    },
}

LIST_CHOICES = {
    "grant_types_supported": GRANT_TYPES,
    "response_types_supported": list(RESPONSE_TYPES.values()),
    "token_endpoint_auth_methods_supported": AUTH_METHODS,
    "token_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_ALGORITHMS,
    "code_challenge_methods_supported": PKCE_METHODS,
    "id_token_signing_alg_values_supported": ID_TOKEN_ALGORITHMS,
    "request_object_signing_alg_values_supported": REQUEST_OBJECT_ALGORITHMS,
}


class InvalidDocument(ValueError):
    """The configuration document is not valid."""

    def __init__(self, errors):
        super().__init__("; ".join(f"{key}: {msg}" for key, msg in errors.items()))
        self.errors = errors


def default_document():
    return copy.deepcopy(DEFAULT_DOCUMENT)


def response_types_for(grant_types):
    """Return the response types of the grants, in a stable order."""
    return [
        RESPONSE_TYPES[grant]
        for grant in GRANT_TYPES
        if grant in grant_types and grant in RESPONSE_TYPES
    ]


def is_oidc_enabled(document):
    return "openid" in document["metadata"]["scopes_supported"]


def claims_supported(scopes):
    """Return the claims that the scopes give (OIDC Core §5.4)."""
    claims = ["sub", "iss", "auth_time", "acr"]
    for scope in scopes:
        claims.extend(
            claim
            for claim in UserInfo.SCOPES_CLAIMS_MAPPING.get(scope, [])
            if claim not in claims
        )
    return claims


def published_metadata(document, issuer, endpoint_urls):
    """Return the metadata that the server publishes."""
    stored = document["metadata"]
    settings = document["settings"]
    oidc = is_oidc_enabled(document)
    grant_types = set(stored["grant_types_supported"])
    # The issuer and the endpoints first, as in the examples of RFC 8414.
    metadata = {"issuer": stored["issuer"] or issuer}
    if grant_types & {"authorization_code", "implicit"}:
        metadata["authorization_endpoint"] = endpoint_urls["authorization_endpoint"]
    if grant_types - {"implicit"}:
        metadata["token_endpoint"] = endpoint_urls["token_endpoint"]
    if settings["revocation_enabled"]:
        metadata["revocation_endpoint"] = endpoint_urls["revocation_endpoint"]
    if oidc:
        metadata["userinfo_endpoint"] = endpoint_urls["userinfo_endpoint"]
        metadata["jwks_uri"] = endpoint_urls["jwks_uri"]

    methods = stored["token_endpoint_auth_methods_supported"]
    jwt_methods = set(methods) & set(JWT_AUTH_METHODS)
    hidden = set() if oidc else set(OIDC_METADATA)
    if not jwt_methods:
        hidden.add("token_endpoint_auth_signing_alg_values_supported")
    # RFC 8414 §2 marks response_types_supported as REQUIRED, even when empty.
    metadata.update(
        {
            key: value
            for key, value in stored.items()
            if key != "issuer"
            and key not in hidden
            and (key == "response_types_supported" or value != [])
        }
    )
    if settings["revocation_enabled"]:
        metadata["revocation_endpoint_auth_methods_supported"] = methods
        # Per RFC 8414 §2, required when a JWT method is listed.
        if jwt_methods:
            metadata["revocation_endpoint_auth_signing_alg_values_supported"] = stored[
                "token_endpoint_auth_signing_alg_values_supported"
            ]
    if oidc:
        metadata.update(
            {
                "subject_types_supported": ["public"],
                "claims_supported": claims_supported(stored["scopes_supported"]),
                "prompt_values_supported": PROMPT_VALUES,
                "ui_locales_supported": UI_LOCALES,
                "claims_parameter_supported": True,
                "request_parameter_supported": True,
                # Per OIDC Discovery §3, the default value is true.
                "request_uri_parameter_supported": False,
            }
        )
    return metadata


def validate_document(document):
    """Raise InvalidDocument if the document is not valid."""
    try:
        metadata = document["metadata"]
        settings = document["settings"]
    except (KeyError, TypeError):
        metadata = settings = None
    if not isinstance(metadata, dict) or not isinstance(settings, dict):
        raise InvalidDocument(
            {"document": "The document needs metadata and settings objects."}
        )

    errors = {**_metadata_errors(metadata), **_settings_errors(settings)}
    if errors:
        raise InvalidDocument(errors)

    expected = response_types_for(metadata["grant_types_supported"])
    if metadata["response_types_supported"] != expected:
        raise InvalidDocument(
            {"response_types_supported": f"The grants give {expected}."}
        )

    # Per RFC 8414 §2, an omitted list would mean client_secret_basic.
    token_grants = set(metadata["grant_types_supported"]) - {"implicit"}
    if token_grants and not metadata["token_endpoint_auth_methods_supported"]:
        raise InvalidDocument(
            {
                "token_endpoint_auth_methods_supported": (
                    "The token endpoint needs at least one method."
                )
            }
        )

    # Only confidential clients use this grant (RFC 6749 §4.4).
    confidential_methods = set(metadata["token_endpoint_auth_methods_supported"]) - {
        "none"
    }
    if "client_credentials" in metadata["grant_types_supported"] and not (
        confidential_methods
    ):
        raise InvalidDocument(
            {
                "token_endpoint_auth_methods_supported": (
                    "The client_credentials grant needs a method for confidential clients."
                )
            }
        )

    if is_oidc_enabled(document) and (
        "authorization_code" not in metadata["grant_types_supported"]
    ):
        raise InvalidDocument(
            {
                "grant_types_supported": (
                    "OpenID Connect needs the authorization_code grant."
                )
            }
        )

    errors = _metadata_model_errors(document)
    if errors:
        raise InvalidDocument(errors)


def _metadata_errors(metadata):
    errors = {
        key: "Unknown key."
        for key in metadata
        if key not in DEFAULT_DOCUMENT["metadata"]
    }
    errors.update(
        {
            key: "Missing key."
            for key in DEFAULT_DOCUMENT["metadata"]
            if key not in metadata
        }
    )

    for key, choices in LIST_CHOICES.items():
        value = metadata.get(key)
        if not isinstance(value, list) or not all(item in choices for item in value):
            errors[key] = f"A list of values among {choices}."

    scopes = metadata.get("scopes_supported")
    if not isinstance(scopes, list) or not all(
        isinstance(scope, str) and scope and " " not in scope for scope in scopes
    ):
        errors["scopes_supported"] = "A list of scopes without spaces."

    issuer = metadata.get("issuer")
    if issuer is not None and not isinstance(issuer, str):
        errors["issuer"] = "A URL, or null."
    if not isinstance(metadata.get("require_signed_request_object"), bool):
        errors["require_signed_request_object"] = "true or false."
    return errors


def _settings_errors(settings):
    errors = {
        key: "Unknown key."
        for key in settings
        if key not in DEFAULT_DOCUMENT["settings"]
    }
    errors.update(
        {
            key: "Missing key."
            for key in DEFAULT_DOCUMENT["settings"]
            if key not in settings
        }
    )

    if settings.get("pkce_required") not in PKCE_REQUIRED:
        errors["pkce_required"] = f"One of {PKCE_REQUIRED}."

    for key in (
        "revocation_enabled",
        "refresh_token_rotation",
        "outbound_private_addresses",
    ):
        if not isinstance(settings.get(key), bool):
            errors[key] = "true or false."

    for key in ("access_token_lifetime", "refresh_token_lifetime", "id_token_lifetime"):
        lifetime = settings.get(key)
        if (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, int)
            or not 1 <= lifetime <= MAX_LIFETIME
        ):
            errors[key] = f"A number of seconds, from 1 to {MAX_LIFETIME}."

    if settings.get("registration") not in REGISTRATION_MODES:
        errors["registration"] = f"One of {REGISTRATION_MODES}."
    token = settings.get("initial_access_token")
    if token is not None and not isinstance(token, str):
        errors["initial_access_token"] = "A string, or null."
    elif settings.get("registration") == "token" and not token:
        errors["initial_access_token"] = "The token mode needs a token."
    return errors


def _metadata_model_errors(document):
    """Check the published metadata with Authlib, one key at a time.

    With OpenID Connect, OpenIDProviderMetadata also checks that RS256 is
    an ID token signing algorithm (OIDC Discovery §3).
    """
    base = document["metadata"]["issuer"] or DEFAULT_ISSUER
    urls = {key: f"{base}/{key}" for key in ENDPOINTS}
    model = (
        OpenIDProviderMetadata
        if is_oidc_enabled(document)
        else AuthorizationServerMetadata
    )
    metadata = model(published_metadata(document, base, urls))
    errors = {}
    # Authlib's OpenIDProviderMetadata leaves out the RFC 7009, 7636 and 7662
    # keys, so the RFC 8414 keys are checked too.
    for key in dict.fromkeys(
        [*AuthorizationServerMetadata.REGISTRY_KEYS, *model.REGISTRY_KEYS]
    ):
        try:
            getattr(metadata, f"validate_{key}")()
        except ValueError as error:
            errors[key] = str(error)
    return errors


def unsupported_values(client_metadata, document):
    """Return the values of a client that the server does not support.

    The result maps a client metadata key to its unsupported values. Keys
    without unsupported values are left out.
    """
    metadata = document["metadata"]
    method = client_metadata.get("token_endpoint_auth_method", "client_secret_basic")
    scopes = (client_metadata.get("scope") or "").split()
    alg = client_metadata.get("id_token_signed_response_alg")
    auth_alg = client_metadata.get("token_endpoint_auth_signing_alg")
    request_alg = client_metadata.get("request_object_signing_alg")
    result = {
        "grant_types": [
            grant
            for grant in client_metadata.get("grant_types", [])
            if grant not in metadata["grant_types_supported"]
        ],
        "response_types": [
            response_type
            for response_type in client_metadata.get("response_types", [])
            if response_type not in metadata["response_types_supported"]
        ],
        "token_endpoint_auth_method": (
            []
            if method in metadata["token_endpoint_auth_methods_supported"]
            else [method]
        ),
        "scope": [
            scope
            for scope in scopes
            if metadata["scopes_supported"]
            and scope not in metadata["scopes_supported"]
        ],
        "id_token_signed_response_alg": (
            [alg]
            if alg
            and is_oidc_enabled(document)
            and alg not in metadata["id_token_signing_alg_values_supported"]
            else []
        ),
        "token_endpoint_auth_signing_alg": (
            [auth_alg]
            if auth_alg
            and auth_alg
            not in metadata["token_endpoint_auth_signing_alg_values_supported"]
            else []
        ),
        "request_object_signing_alg": (
            [request_alg]
            if request_alg
            and is_oidc_enabled(document)
            and request_alg
            not in metadata["request_object_signing_alg_values_supported"]
            else []
        ),
    }
    return {key: values for key, values in result.items() if values}
