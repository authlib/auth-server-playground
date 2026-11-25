import httpx2
import pytest
from joserfc.jwk import RSAKey

from auth_server_playground.models import Client
from tests.utils import REDIRECT_URI
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import exchange_code
from tests.utils import oidc_url

REGISTRATION = {
    "redirect_uris": [REDIRECT_URI],
    "client_name": "Dynamic client",
    "scope": "openid profile",
}


def register(testapp, metadata=None, *, token=None, status=201):
    return testapp.post_json(
        "/oauth/register",
        REGISTRATION if metadata is None else metadata,
        headers=bearer(token) if token else {},
        status=status,
    )


def test_registration_endpoint_is_published(testapp):
    metadata = testapp.get("/.well-known/openid-configuration").json
    assert metadata["registration_endpoint"] == "http://localhost/oauth/register"


def test_open_registration(app, testapp):
    body = register(testapp).json
    client_id = body["client_id"]
    assert body["client_name"] == "Dynamic client"
    assert body["client_secret"]
    assert body["client_secret_expires_at"] == 0
    assert body["grant_types"] == ["authorization_code"]
    assert body["response_types"] == ["code"]
    assert body["token_endpoint_auth_method"] == "client_secret_basic"
    assert (
        body["registration_client_uri"]
        == f"http://localhost/oauth/register/{client_id}"
    )
    with app.app_context():
        client = Client.query.filter_by(client_id=client_id).one()
        assert client.registration_access_token == body["registration_access_token"]
        assert client.is_dynamic


def test_registered_client_runs_the_code_flow(logged_in):
    client = register(logged_in).json
    code = callback_params(consent(logged_in, oidc_url(client)))["code"]
    assert exchange_code(logged_in, client, code).json["id_token"]


def test_client_without_scope_gets_the_server_scopes(app, testapp):
    body = register(testapp, {"redirect_uris": [REDIRECT_URI]}).json
    assert body["scope"] == "openid profile email address phone"
    with app.app_context():
        client = Client.query.filter_by(client_id=body["client_id"]).one()
        assert client.scope == body["scope"]


def test_client_without_scope_runs_the_openid_flow(logged_in):
    client = register(logged_in, {"redirect_uris": [REDIRECT_URI]}).json
    code = callback_params(consent(logged_in, oidc_url(client)))["code"]
    assert exchange_code(logged_in, client, code).json["id_token"]


def test_client_without_scope_on_a_server_without_scopes(testapp, configure):
    configure(metadata={"scopes_supported": []})
    body = register(testapp, {"redirect_uris": [REDIRECT_URI]}).json
    assert "scope" not in body


def test_client_scope_is_kept(testapp):
    body = register(testapp).json
    assert body["scope"] == "openid profile"


def test_public_client_gets_no_secret(testapp):
    body = register(
        testapp, {**REGISTRATION, "token_endpoint_auth_method": "none"}
    ).json
    assert "client_secret" not in body
    assert "client_secret_expires_at" not in body


def test_open_registration_ignores_a_token(testapp):
    register(testapp, token="anything")


def test_disabled_registration(testapp, configure):
    configure(settings={"registration": "disabled"})
    register(testapp, status=404)
    metadata = testapp.get("/.well-known/openid-configuration").json
    assert "registration_endpoint" not in metadata


@pytest.fixture
def token_mode(configure):
    configure(settings={"registration": "token", "initial_access_token": "iat-value"})


def test_token_mode_needs_the_token(testapp, token_mode):
    register(testapp, status=401)


def test_token_mode_refuses_a_wrong_token(testapp, token_mode):
    res = register(testapp, token="wrong", status=401)
    assert res.json["error"] == "invalid_token"


def test_token_mode_accepts_the_token(testapp, token_mode):
    register(testapp, token="iat-value")


@pytest.mark.parametrize(
    "metadata",
    [
        {**REGISTRATION, "redirect_uris": ["not a url"]},
        {**REGISTRATION, "grant_types": ["password"]},
        {**REGISTRATION, "token_endpoint_auth_method": "tls_client_auth"},
        {**REGISTRATION, "userinfo_encrypted_response_alg": "RSA-OAEP"},
        {**REGISTRATION, "subject_type": "pairwise"},
    ],
)
def test_invalid_metadata(testapp, metadata):
    res = register(testapp, metadata, status=400)
    assert res.json["error"] == "invalid_client_metadata"


def test_register_signed_userinfo(testapp):
    body = register(
        testapp, {**REGISTRATION, "userinfo_signed_response_alg": "RS256"}
    ).json
    assert body["userinfo_signed_response_alg"] == "RS256"


def test_register_unsigned_id_token(testapp, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "none"]})
    body = register(
        testapp, {**REGISTRATION, "id_token_signed_response_alg": "none"}
    ).json
    assert body["id_token_signed_response_alg"] == "none"


def test_unsigned_id_token_when_not_published(testapp):
    res = register(
        testapp,
        {**REGISTRATION, "id_token_signed_response_alg": "none"},
        status=400,
    )
    assert res.json["error"] == "invalid_client_metadata"


def test_signed_userinfo_with_an_unpublished_algorithm(testapp):
    res = register(
        testapp,
        {**REGISTRATION, "userinfo_signed_response_alg": "PS256"},
        status=400,
    )
    assert res.json["error"] == "invalid_client_metadata"


def test_signed_userinfo_when_the_server_does_not_sign(testapp, configure):
    configure(metadata={"userinfo_signing_alg_values_supported": []})
    res = register(
        testapp,
        {**REGISTRATION, "userinfo_signed_response_alg": "RS256"},
        status=400,
    )
    assert res.json["error"] == "invalid_client_metadata"


def test_openid_metadata_dropped_without_openid(testapp, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    body = register(
        testapp,
        {**REGISTRATION, "scope": "profile", "id_token_signed_response_alg": "RS256"},
    ).json
    assert "id_token_signed_response_alg" not in body


def test_software_statement_is_ignored(testapp):
    body = register(testapp, {**REGISTRATION, "software_statement": "a.b.c"}).json
    assert "software_statement" not in body


def test_body_must_be_an_object(testapp):
    res = register(testapp, [], status=400)
    assert res.json["error"] == "invalid_request"


def test_request_uris_are_stored(app, testapp):
    uris = ["https://client.test/a.jwt", "https://client.test/b.jwt"]
    body = register(testapp, {**REGISTRATION, "request_uris": uris}).json
    assert body["request_uris"] == uris


def test_request_uris_over_http_with_insecure_transport(testapp):
    uris = ["http://client.test/a.jwt"]
    body = register(testapp, {**REGISTRATION, "request_uris": uris}).json
    assert body["request_uris"] == uris


@pytest.mark.parametrize("insecure_transport", [False])
@pytest.mark.parametrize(
    "uris",
    [
        ["http://client.test/a.jwt"],
        ["http://localhost/a.jwt"],
        ["ftp://client.test/a.jwt"],
        ["not a url"],
    ],
)
def test_invalid_request_uris(testapp, uris):
    res = register(testapp, {**REGISTRATION, "request_uris": uris}, status=400)
    assert res.json["error"] == "invalid_client_metadata"


def test_private_key_jwt_client_gets_no_secret(testapp, rsa_pool):
    key = RSAKey.import_key(rsa_pool[0]).as_dict(private=False)
    body = register(
        testapp,
        {
            **REGISTRATION,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [key]},
        },
    ).json
    assert "client_secret" not in body


@pytest.mark.parametrize(
    "metadata",
    [
        {"token_endpoint_auth_method": "private_key_jwt"},
        {
            "token_endpoint_auth_method": "client_secret_jwt",
            "token_endpoint_auth_signing_alg": "RS256",
        },
        {
            "jwks": {
                "keys": [
                    {"kty": "oct", "k": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"}
                ]
            }
        },
        {"jwks": {"keys": []}, "jwks_uri": "https://client.test/jwks.json"},
    ],
)
def test_invalid_key_metadata(testapp, metadata):
    res = register(testapp, {**REGISTRATION, **metadata}, status=400)
    assert res.json["error"] == "invalid_client_metadata"


SECTOR_URI = "https://sector.test/uris.json"
PAIRWISE = {**REGISTRATION, "subject_type": "pairwise"}


def serve_sector(outbound_urls, content):
    outbound_urls.responses[SECTOR_URI] = httpx2.Response(200, content=content)


def test_pairwise_client_registers(testapp, pairwise_server):
    body = register(testapp, PAIRWISE).json
    assert body["subject_type"] == "pairwise"


def test_pairwise_is_refused_when_the_server_publishes_only_public(testapp):
    res = register(testapp, PAIRWISE, status=400)
    assert res.json["error"] == "invalid_client_metadata"


def test_sector_identifier_uri_that_lists_the_redirect_uri(
    testapp, pairwise_server, outbound_urls
):
    serve_sector(outbound_urls, f'["{REDIRECT_URI}"]'.encode())
    metadata = {**PAIRWISE, "sector_identifier_uri": SECTOR_URI}
    body = register(testapp, metadata).json
    assert body["sector_identifier_uri"] == SECTOR_URI
    assert outbound_urls.requested == [SECTOR_URI]


@pytest.mark.parametrize(
    "content",
    [
        b'["http://other.test/callback"]',
        b"not json",
        b'{"uris": []}',
        b"[42]",
        None,
    ],
)
def test_invalid_sector_document_is_refused(
    testapp, pairwise_server, outbound_urls, content
):
    if content is not None:
        serve_sector(outbound_urls, content)

    metadata = {**PAIRWISE, "sector_identifier_uri": SECTOR_URI}
    res = register(testapp, metadata, status=400)
    assert res.json["error"] == "invalid_client_metadata"


@pytest.mark.parametrize("insecure_transport", [False])
def test_http_sector_identifier_uri_is_refused(testapp, pairwise_server, outbound_urls):
    metadata = {**PAIRWISE, "sector_identifier_uri": "http://sector.test/uris.json"}
    res = register(testapp, metadata, status=400)
    assert res.json["error"] == "invalid_client_metadata"
    assert outbound_urls.requested == []


def test_pairwise_client_on_two_hosts_needs_a_sector(testapp, pairwise_server):
    metadata = {
        **PAIRWISE,
        "redirect_uris": [REDIRECT_URI, "http://other.test/callback"],
    }
    res = register(testapp, metadata, status=400)
    assert res.json["error"] == "invalid_client_metadata"


def test_public_client_on_two_hosts_registers(testapp, pairwise_server):
    metadata = {**REGISTRATION, "redirect_uris": [REDIRECT_URI, "http://other.test/"]}
    register(testapp, metadata)
