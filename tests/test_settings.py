import pytest

from auth_server_playground.settings import InvalidDocument
from auth_server_playground.settings import default_document
from auth_server_playground.settings import published_metadata
from auth_server_playground.settings import response_types_for
from auth_server_playground.settings import unsupported_values
from auth_server_playground.settings import validate_document

URLS = {
    "authorization_endpoint": "https://server.test/oauth/authorize",
    "token_endpoint": "https://server.test/oauth/token",
    "revocation_endpoint": "https://server.test/oauth/revoke",
}


def changed(metadata=None, settings=None):
    document = default_document()
    document["metadata"].update(metadata or {})
    document["settings"].update(settings or {})
    return document


def errors_of(document):
    with pytest.raises(InvalidDocument) as excinfo:
        validate_document(document)
    return excinfo.value.errors


def test_default_document_follows_rfc_9700():
    document = default_document()
    assert document["metadata"]["grant_types_supported"] == [
        "authorization_code",
        "refresh_token",
        "client_credentials",
    ]
    assert document["metadata"]["code_challenge_methods_supported"] == ["S256"]
    assert document["settings"]["pkce_required"] == "all"
    assert document["settings"]["refresh_token_rotation"] is True
    validate_document(document)


def test_default_document_is_a_copy():
    default_document()["metadata"]["scopes_supported"].append("admin")
    assert "admin" not in default_document()["metadata"]["scopes_supported"]


def test_response_types_follow_the_grants():
    grant_types = ["refresh_token", "implicit", "authorization_code"]
    assert response_types_for(grant_types) == ["code", "token"]
    assert response_types_for(["client_credentials"]) == []


def test_response_types_must_match_the_grants():
    document = changed(metadata={"response_types_supported": ["code", "token"]})
    assert "response_types_supported" in errors_of(document)


@pytest.mark.parametrize(
    "key,value",
    [
        ("grant_types_supported", ["device_code"]),
        ("token_endpoint_auth_methods_supported", ["private_key_jwt"]),
        ("code_challenge_methods_supported", ["S512"]),
        ("response_types_supported", "code"),
        ("scopes_supported", ["two words"]),
        ("scopes_supported", "profile"),
        ("issuer", 42),
    ],
)
def test_invalid_metadata_values_are_refused(key, value):
    assert key in errors_of(changed(metadata={key: value}))


@pytest.mark.parametrize(
    "key,value",
    [
        ("pkce_required", "never"),
        ("revocation_enabled", "yes"),
        ("refresh_token_rotation", 1),
        ("access_token_lifetime", 0),
        ("access_token_lifetime", True),
        ("access_token_lifetime", "3600"),
    ],
)
def test_invalid_settings_are_refused(key, value):
    assert key in errors_of(changed(settings={key: value}))


def test_unknown_keys_are_refused():
    document = default_document()
    document["metadata"]["jwks_uri"] = "https://server.test/jwks"
    document["settings"]["color"] = "mauve"
    errors = errors_of(document)
    assert "jwks_uri" in errors
    assert "color" in errors


def test_missing_keys_are_refused():
    document = default_document()
    del document["metadata"]["issuer"]
    assert "issuer" in errors_of(document)


@pytest.mark.parametrize("document", [{"metadata": {}}, []])
def test_document_needs_metadata_and_settings(document):
    assert "document" in errors_of(document)


@pytest.mark.parametrize("insecure_transport", [False])
def test_issuer_uses_https(app):
    errors = errors_of(changed(metadata={"issuer": "http://server.test"}))
    assert "issuer" in errors


def test_https_issuer():
    validate_document(changed(metadata={"issuer": "https://server.test"}))


def test_published_metadata_computes_the_endpoints():
    metadata = published_metadata(default_document(), "https://server.test", URLS)
    assert metadata["issuer"] == "https://server.test"
    assert metadata["authorization_endpoint"] == URLS["authorization_endpoint"]
    assert metadata["token_endpoint"] == URLS["token_endpoint"]
    assert metadata["revocation_endpoint"] == URLS["revocation_endpoint"]
    assert metadata["revocation_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]


def test_published_metadata_uses_the_configured_issuer():
    document = changed(metadata={"issuer": "https://issuer.test"})
    metadata = published_metadata(document, "https://server.test", URLS)
    assert metadata["issuer"] == "https://issuer.test"


def test_published_metadata_leaves_out_disabled_endpoints():
    document = changed(
        metadata={
            "grant_types_supported": ["client_credentials"],
            "response_types_supported": [],
        },
        settings={"revocation_enabled": False},
    )
    metadata = published_metadata(document, "https://server.test", URLS)
    assert "authorization_endpoint" not in metadata
    assert "revocation_endpoint" not in metadata
    assert "revocation_endpoint_auth_methods_supported" not in metadata
    assert metadata["response_types_supported"] == []


def test_published_metadata_without_token_endpoint():
    document = changed(
        metadata={
            "grant_types_supported": ["implicit"],
            "response_types_supported": ["token"],
        },
    )
    metadata = published_metadata(document, "https://server.test", URLS)
    assert "token_endpoint" not in metadata


def test_published_metadata_leaves_out_empty_lists():
    document = changed(metadata={"code_challenge_methods_supported": []})
    metadata = published_metadata(document, "https://server.test", URLS)
    assert "code_challenge_methods_supported" not in metadata


def test_unsupported_values():
    client_metadata = {
        "grant_types": ["authorization_code", "password"],
        "response_types": ["code", "token"],
        "token_endpoint_auth_method": "client_secret_jwt",
        "scope": "profile admin",
    }
    assert unsupported_values(client_metadata, default_document()) == {
        "grant_types": ["password"],
        "response_types": ["token"],
        "token_endpoint_auth_method": ["client_secret_jwt"],
        "scope": ["admin"],
    }


def test_no_unsupported_values():
    client_metadata = {"grant_types": ["client_credentials"], "scope": "profile"}
    assert unsupported_values(client_metadata, default_document()) == {}


def test_any_scope_is_supported_without_scopes_supported():
    document = changed(metadata={"scopes_supported": []})
    assert unsupported_values({"scope": "admin"}, document) == {}


def test_client_credentials_needs_a_confidential_method():
    document = changed(metadata={"token_endpoint_auth_methods_supported": ["none"]})
    assert "token_endpoint_auth_methods_supported" in errors_of(document)
