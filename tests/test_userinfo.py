import pytest
from joserfc import jwt
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jwk import KeySet

from auth_server_playground.keys import active_kid
from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.settings import USERINFO_ALGORITHMS
from tests.conftest import make_client
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import client_credentials_token
from tests.utils import consent
from tests.utils import exchange_code
from tests.utils import oidc_url

SIGNED_CLIENT = {
    "scope": "openid profile",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
}


def access_token(testapp, client, scope):
    code = callback_params(consent(testapp, oidc_url(client, scope=scope)))["code"]
    return exchange_code(testapp, client, code).json["access_token"]


def test_userinfo_get(logged_in, client):
    token = access_token(logged_in, client, "openid profile")
    res = logged_in.get("/oauth/userinfo", headers=bearer(token))
    assert res.json["sub"] == COMPLETE_SUB
    assert res.json["name"] == "Alice Martin"
    assert res.json["picture"].startswith("http://localhost/personas/")
    assert "email" not in res.json


def test_userinfo_post_with_the_header(logged_in, client):
    token = access_token(logged_in, client, "openid")
    res = logged_in.post("/oauth/userinfo", headers=bearer(token))
    assert res.json == {"sub": COMPLETE_SUB}


def test_userinfo_needs_the_openid_scope(logged_in, client):
    token = access_token(logged_in, client, "profile")
    res = logged_in.get("/oauth/userinfo", headers=bearer(token), status=403)
    assert res.json["error"] == "insufficient_scope"


def test_userinfo_refuses_a_token_without_persona(testapp, client):
    token = client_credentials_token(testapp, client, scope="openid").json
    res = testapp.get(
        "/oauth/userinfo", headers=bearer(token["access_token"]), status=401
    )
    assert res.json["error"] == "invalid_token"


def test_userinfo_needs_a_token(testapp):
    testapp.get("/oauth/userinfo", status=401)


def test_userinfo_without_openid(testapp, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    testapp.get("/oauth/userinfo", status=404)


@pytest.mark.parametrize("alg", USERINFO_ALGORITHMS)
def test_signed_userinfo(app, logged_in, configure, alg):
    configure(metadata={"userinfo_signing_alg_values_supported": [alg]})
    client = make_client(
        app,
        client_id="signed-client",
        client_secret="signed-secret",
        metadata={**SIGNED_CLIENT, "userinfo_signed_response_alg": alg},
    )
    token = access_token(logged_in, client, "openid profile")
    res = logged_in.get("/oauth/userinfo", headers=bearer(token))
    assert res.content_type == "application/jwt"
    key_set = KeySet.import_key_set(logged_in.get("/oauth/jwks").json)
    signed = jwt.decode(res.text, key_set, algorithms=[alg])
    with app.app_context():
        assert signed.header["kid"] == active_kid(alg)

    assert signed.claims["iss"] == "http://localhost"
    assert signed.claims["aud"] == "signed-client"
    assert signed.claims["sub"] == COMPLETE_SUB
    assert signed.claims["name"] == "Alice Martin"


def test_userinfo_is_json_without_the_client_metadata(logged_in, client):
    token = access_token(logged_in, client, "openid")
    res = logged_in.get("/oauth/userinfo", headers=bearer(token))
    assert res.content_type == "application/json"


def test_stale_userinfo_algorithm_raises(app, logged_in):
    """Authlib signs without checking the published list, so the request raises."""
    client = make_client(
        app,
        client_id="stale-client",
        client_secret="stale-secret",
        metadata={**SIGNED_CLIENT, "userinfo_signed_response_alg": "ES256"},
    )
    token = access_token(logged_in, client, "openid profile")
    with pytest.raises(UnsupportedAlgorithmError):
        logged_in.get("/oauth/userinfo", headers=bearer(token))
