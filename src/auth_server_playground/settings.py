"""The configuration document of the server.

This module does not touch the database. ``store.py`` reads and writes the
document.
"""

import copy

from authlib.oauth2.rfc8414 import AuthorizationServerMetadata

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

#: The issuer used to validate a document whose issuer comes from requests.
DEFAULT_ISSUER = "http://localhost"

ENDPOINTS = ["authorization_endpoint", "token_endpoint", "revocation_endpoint"]

#: The longest token lifetime, so that expiration dates fit in the database.
MAX_LIFETIME = 365 * 24 * 3600

# Defaults per RFC 9700.
DEFAULT_DOCUMENT = {
    "metadata": {
        "issuer": None,
        "scopes_supported": ["profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "token_endpoint_auth_methods_supported": list(AUTH_METHODS),
        "code_challenge_methods_supported": ["S256"],
    },
    "settings": {
        "pkce_required": "all",
        "revocation_enabled": True,
        "access_token_lifetime": 3600,
        "refresh_token_lifetime": 14 * 24 * 3600,
        "refresh_token_rotation": True,
    },
}

LIST_CHOICES = {
    "grant_types_supported": GRANT_TYPES,
    "response_types_supported": list(RESPONSE_TYPES.values()),
    "token_endpoint_auth_methods_supported": AUTH_METHODS,
    "code_challenge_methods_supported": PKCE_METHODS,
}


class InvalidDocument(ValueError):
    """The configuration document is not valid.

    ``errors`` maps a metadata or settings key, or ``"document"``, to a message.
    """

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


def published_metadata(document, issuer, endpoint_urls):
    """Return the metadata that the server publishes.

    ``issuer`` is used when the document has none. ``endpoint_urls`` maps the
    endpoint metadata keys to their URLs.
    """
    stored = document["metadata"]
    settings = document["settings"]
    grant_types = set(stored["grant_types_supported"])
    # The issuer and the endpoints first, as in the examples of RFC 8414.
    metadata = {"issuer": stored["issuer"] or issuer}
    if grant_types & {"authorization_code", "implicit"}:
        metadata["authorization_endpoint"] = endpoint_urls["authorization_endpoint"]
    if grant_types - {"implicit"}:
        metadata["token_endpoint"] = endpoint_urls["token_endpoint"]
    if settings["revocation_enabled"]:
        metadata["revocation_endpoint"] = endpoint_urls["revocation_endpoint"]

    # RFC 8414 §2 marks response_types_supported as REQUIRED, even when empty.
    metadata.update(
        {
            key: value
            for key, value in stored.items()
            if key != "issuer" and (key == "response_types_supported" or value != [])
        }
    )
    if settings["revocation_enabled"]:
        metadata["revocation_endpoint_auth_methods_supported"] = stored[
            "token_endpoint_auth_methods_supported"
        ]
    return metadata


def validate_document(document):
    """Raise InvalidDocument if the document is not valid."""
    try:
        metadata = document["metadata"]
        settings = document["settings"]
    except (KeyError, TypeError):
        raise InvalidDocument(
            {"document": "The document needs metadata and settings."}
        ) from None

    errors = {**_metadata_errors(metadata), **_settings_errors(settings)}
    if errors:
        raise InvalidDocument(errors)

    expected = response_types_for(metadata["grant_types_supported"])
    if metadata["response_types_supported"] != expected:
        raise InvalidDocument(
            {"response_types_supported": f"The grants give {expected}."}
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

    errors = _rfc8414_errors(document)
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
    return errors


def _settings_errors(settings):
    errors = {
        key: "Unknown key."
        for key in settings
        if key not in DEFAULT_DOCUMENT["settings"]
    }

    if settings.get("pkce_required") not in PKCE_REQUIRED:
        errors["pkce_required"] = f"One of {PKCE_REQUIRED}."

    for key in ("revocation_enabled", "refresh_token_rotation"):
        if not isinstance(settings.get(key), bool):
            errors[key] = "true or false."

    for key in ("access_token_lifetime", "refresh_token_lifetime"):
        lifetime = settings.get(key)
        if (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, int)
            or not 1 <= lifetime <= MAX_LIFETIME
        ):
            errors[key] = f"A number of seconds, from 1 to {MAX_LIFETIME}."
    return errors


def _rfc8414_errors(document):
    """Check the published metadata with Authlib, one key at a time."""
    base = document["metadata"]["issuer"] or DEFAULT_ISSUER
    urls = {key: f"{base}/{key}" for key in ENDPOINTS}
    metadata = AuthorizationServerMetadata(published_metadata(document, base, urls))
    errors = {}
    for key in AuthorizationServerMetadata.REGISTRY_KEYS:
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
    }
    return {key: values for key, values in result.items() if values}
