import httpx2
import pytest
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from auth_server_playground.client_keys import ClientKeysError
from auth_server_playground.client_keys import client_key_errors
from auth_server_playground.client_keys import public_keys
from auth_server_playground.client_keys import secret_key
from auth_server_playground.models import Client

JWKS_URI = "https://client.test/jwks.json"


@pytest.fixture
def public_jwks(rsa_pool):
    return {"keys": [RSAKey.import_key(rsa_pool[0]).as_dict(private=False)]}


def client_with(metadata, secret=""):
    client = Client(client_id="c", client_secret=secret)
    client.set_client_metadata(metadata)
    return client


def test_inline_keys(public_jwks):
    keys = public_keys(client_with({"jwks": public_jwks}), allow_private_addresses=True)
    assert isinstance(keys, KeySet)
    assert len(keys.keys) == 1


def test_keys_from_jwks_uri(outbound_urls, public_jwks):
    outbound_urls.responses[JWKS_URI] = httpx2.Response(200, json=public_jwks)
    client = client_with({"jwks_uri": JWKS_URI})
    keys = public_keys(client, allow_private_addresses=True)
    assert len(keys.keys) == 1
    assert outbound_urls.requested == [JWKS_URI]


def test_jwks_uri_is_fetched_on_each_use(outbound_urls, public_jwks):
    outbound_urls.responses[JWKS_URI] = httpx2.Response(200, json=public_jwks)
    client = client_with({"jwks_uri": JWKS_URI})
    public_keys(client, allow_private_addresses=True)
    public_keys(client, allow_private_addresses=True)
    assert outbound_urls.requested == [JWKS_URI, JWKS_URI]


@pytest.mark.parametrize(
    "response,reason",
    [
        (httpx2.Response(404), "HTTP status 404"),
        (httpx2.Response(200, content=b"not json"), "not JSON"),
        (httpx2.Response(200, json={"keys": "none"}), "not a JWK Set"),
    ],
)
def test_jwks_uri_errors(outbound_urls, response, reason):
    outbound_urls.responses[JWKS_URI] = response
    with pytest.raises(ClientKeysError) as error:
        public_keys(client_with({"jwks_uri": JWKS_URI}), allow_private_addresses=True)
    assert reason in error.value.description
    assert "jwks_uri" in error.value.description


def test_client_without_keys():
    with pytest.raises(ClientKeysError, match="no keys"):
        public_keys(client_with({}), allow_private_addresses=True)


def test_secret_key():
    key = secret_key(client_with({}, secret="a-long-enough-client-secret"))
    assert isinstance(key, OctKey)


def test_secret_key_needs_a_secret():
    with pytest.raises(ClientKeysError, match="no secret"):
        secret_key(client_with({}))


@pytest.mark.parametrize(
    "metadata,keys",
    [
        ({"token_endpoint_auth_method": "private_key_jwt"}, {"jwks"}),
        (
            {"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": JWKS_URI},
            set(),
        ),
        (
            {
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": JWKS_URI,
                "token_endpoint_auth_signing_alg": "HS256",
            },
            {"token_endpoint_auth_signing_alg"},
        ),
        (
            {
                "token_endpoint_auth_method": "client_secret_jwt",
                "token_endpoint_auth_signing_alg": "RS256",
            },
            {"token_endpoint_auth_signing_alg"},
        ),
        (
            {
                "token_endpoint_auth_method": "client_secret_jwt",
                "token_endpoint_auth_signing_alg": "HS256",
            },
            set(),
        ),
        ({"token_endpoint_auth_signing_alg": "RS256"}, set()),
        ({}, set()),
    ],
)
def test_client_key_errors(metadata, keys):
    assert set(client_key_errors(metadata)) == keys
