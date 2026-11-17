import time

import httpx2
import pytest
from authlib.common.security import generate_token
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey

from tests.conftest import make_client
from tests.utils import bearer

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TOKEN_URL = "http://localhost/oauth/token"
SECRET = "a-client-secret-of-forty-eight-characters-123456"
JWKS_URI = "https://client.test/jwks.json"


def assertion(client_id, key, alg, *, aud=TOKEN_URL, jti=None):
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "iat": now,
        "exp": now + 60,
        "jti": jti or generate_token(16),
    }
    return jwt.encode({"alg": alg}, claims, key, algorithms=[alg])


def token_request(testapp, client_assertion, *, status=200):
    return testapp.post(
        "/oauth/token",
        {
            "grant_type": "client_credentials",
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
        status=status,
    )


def refused(testapp, client_assertion, reason=""):
    res = token_request(testapp, client_assertion, status="4*")
    assert res.json["error"] == "invalid_client"
    assert reason in res.json["error_description"]
    return res


def jwt_client(app, client_id, metadata, secret=""):
    make_client(
        app,
        client_id=client_id,
        client_secret=secret,
        metadata={
            "grant_types": ["client_credentials"],
            "response_types": [],
            **metadata,
        },
    )
    return client_id


@pytest.fixture
def rsa_key(rsa_pool):
    return RSAKey.import_key(rsa_pool[0])


@pytest.fixture
def key_client(app, rsa_key):
    return jwt_client(
        app,
        "key-client",
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [rsa_key.as_dict(private=False)]},
        },
    )


@pytest.fixture
def secret_client(app):
    return jwt_client(
        app,
        "secret-client",
        {"token_endpoint_auth_method": "client_secret_jwt"},
        SECRET,
    )


@pytest.mark.parametrize("alg", ["RS256", "PS256"])
def test_private_key_jwt(testapp, key_client, rsa_key, alg):
    token_request(testapp, assertion(key_client, rsa_key, alg))


@pytest.mark.parametrize(
    "key,alg",
    [
        (ECKey.generate_key("P-256"), "ES256"),
        (OKPKey.generate_key("Ed25519"), "Ed25519"),
    ],
)
def test_private_key_jwt_with_other_keys(app, testapp, key, alg):
    client_id = jwt_client(
        app,
        "other-key-client",
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [key.as_dict(private=False)]},
        },
    )
    token_request(testapp, assertion(client_id, key, alg))


def test_client_secret_jwt(testapp, secret_client):
    token_request(testapp, assertion(secret_client, OctKey.import_key(SECRET), "HS256"))


def test_hs256_refused_for_private_key_jwt(testapp, key_client):
    refused(
        testapp,
        assertion(key_client, OctKey.import_key(SECRET), "HS256"),
        "not allowed",
    )


def test_rs256_refused_for_client_secret_jwt(testapp, secret_client, rsa_key):
    refused(testapp, assertion(secret_client, rsa_key, "RS256"), "not allowed")


def test_client_of_another_method(testapp, client, rsa_key):
    refused(
        testapp, assertion(client["client_id"], rsa_key, "RS256"), "cannot authenticate"
    )


def test_server_algorithms(testapp, configure, key_client, rsa_key):
    configure(metadata={"token_endpoint_auth_signing_alg_values_supported": ["RS256"]})
    token_request(testapp, assertion(key_client, rsa_key, "RS256"))
    refused(testapp, assertion(key_client, rsa_key, "PS256"), "not allowed")


def test_no_algorithm_for_the_method(testapp, configure, secret_client):
    configure(metadata={"token_endpoint_auth_signing_alg_values_supported": ["RS256"]})
    refused(
        testapp,
        assertion(secret_client, OctKey.import_key(SECRET), "HS256"),
        "no algorithm",
    )


def test_client_algorithm(app, testapp, rsa_key):
    client_id = jwt_client(
        app,
        "rs256-client",
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "RS256",
            "jwks": {"keys": [rsa_key.as_dict(private=False)]},
        },
    )
    token_request(testapp, assertion(client_id, rsa_key, "RS256"))
    refused(testapp, assertion(client_id, rsa_key, "PS256"), "RS256")


def test_issuer_as_audience(testapp, key_client, rsa_key):
    token_request(
        testapp, assertion(key_client, rsa_key, "RS256", aud="http://localhost")
    )


def test_other_audience(testapp, key_client, rsa_key):
    refused(
        testapp,
        assertion(key_client, rsa_key, "RS256", aud="https://other.test"),
        "aud",
    )


def test_replayed_assertion(testapp, key_client, rsa_key):
    replayed = assertion(key_client, rsa_key, "RS256")
    token_request(testapp, replayed)
    refused(testapp, replayed, "used before")


def test_same_jti_for_two_clients(testapp, key_client, secret_client, rsa_key):
    token_request(testapp, assertion(key_client, rsa_key, "RS256", jti="shared"))
    token_request(
        testapp,
        assertion(secret_client, OctKey.import_key(SECRET), "HS256", jti="shared"),
    )


def test_keys_from_jwks_uri(app, testapp, outbound_urls, rsa_key):
    outbound_urls.responses[JWKS_URI] = httpx2.Response(
        200, json={"keys": [rsa_key.as_dict(private=False)]}
    )
    client_id = jwt_client(
        app,
        "uri-client",
        {"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": JWKS_URI},
    )
    token_request(testapp, assertion(client_id, rsa_key, "RS256"))


def test_jwks_uri_error(app, testapp, outbound_urls, rsa_key):
    client_id = jwt_client(
        app,
        "uri-client",
        {"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": JWKS_URI},
    )
    res = refused(testapp, assertion(client_id, rsa_key, "RS256"))
    assert "jwks_uri" in res.json["error_description"]


def test_method_disabled_on_the_server(testapp, configure, key_client, rsa_key):
    configure(
        metadata={"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
    )
    refused(testapp, assertion(key_client, rsa_key, "RS256"))


def test_method_disabled_on_every_endpoint(testapp, configure, key_client, rsa_key):
    configure(
        metadata={
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
    )
    refused(testapp, assertion(key_client, rsa_key, "RS256"))


def test_revocation_with_private_key_jwt(app, testapp, key_client, rsa_key):
    token = token_request(testapp, assertion(key_client, rsa_key, "RS256")).json
    testapp.post(
        "/oauth/revoke",
        {
            "token": token["access_token"],
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion(key_client, rsa_key, "RS256"),
        },
    )
    testapp.get("/api/resource", headers=bearer(token["access_token"]), status=401)


def test_malformed_assertion(testapp, key_client):
    refused(testapp, "not-a-jwt", "Invalid JWT")


def test_huge_exp_is_refused(testapp, key_client, rsa_key):
    claims = {
        "iss": key_client,
        "sub": key_client,
        "aud": TOKEN_URL,
        "exp": 10**30,
        "jti": generate_token(16),
    }
    token = jwt.encode({"alg": "RS256"}, claims, rsa_key, algorithms=["RS256"])
    refused(testapp, token, "exp")


def test_no_algorithm_fetches_nothing(app, testapp, configure, outbound_urls, rsa_key):
    client_id = jwt_client(
        app,
        "uri-client",
        {"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": JWKS_URI},
    )
    configure(metadata={"token_endpoint_auth_signing_alg_values_supported": ["HS256"]})
    refused(testapp, assertion(client_id, rsa_key, "RS256"), "no algorithm")
    assert outbound_urls.requested == []


def test_revocation_needs_the_assertion(testapp, key_client, rsa_key):
    token = token_request(testapp, assertion(key_client, rsa_key, "RS256")).json
    other = RSAKey.generate_key(2048)
    res = testapp.post(
        "/oauth/revoke",
        {
            "token": token["access_token"],
            "client_id": key_client,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion(key_client, other, "RS256"),
        },
        status="4*",
    )
    assert res.json["error"] == "invalid_client"
    testapp.get("/api/resource", headers=bearer(token["access_token"]))
