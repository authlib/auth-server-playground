import pytest
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.jwk import RSAKey

from auth_server_playground.personas import MINIMAL_SUB
from tests.utils import CODE_VERIFIER
from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import decode_id_token
from tests.utils import exchange_code

# joserfc warns on each use of alg none.
pytestmark = pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")


def request_claims(client, **params):
    """Return the claims of a request object for the code flow."""
    return {
        "client_id": client["client_id"],
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": "from-the-object",
        "nonce": generate_token(16),
        "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
        "code_challenge_method": "S256",
        **params,
    }


def unsigned(claims):
    return jwt.encode({"alg": "none"}, claims, None, algorithms=["none"])


def test_unsigned_request_object(logged_in, client):
    claims = request_claims(client)
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    params = callback_params(consent(logged_in, url))
    assert params["state"] == "from-the-object"
    id_token = exchange_code(logged_in, client, params["code"]).json["id_token"]
    assert decode_id_token(logged_in, id_token).claims["nonce"] == claims["nonce"]


def test_unsigned_request_object_sent_with_post(logged_in, client):
    res = logged_in.post(
        "/oauth/authorize",
        {"client_id": client["client_id"], "request": unsigned(request_claims(client))},
        status=303,
    )
    params = callback_params(res.follow().forms["consent"].submit("accept"))
    assert params["state"] == "from-the-object"
    assert "code" in params


def test_signed_request_object_is_refused(logged_in, client, rsa_pool):
    key = RSAKey.import_key(rsa_pool[0])
    request = jwt.encode({"alg": "RS256"}, request_claims(client), key)
    url = authorize_url(client_id=client["client_id"], request=request)
    res = logged_in.get(url, status=400)
    assert res.json["error"] == "invalid_request"


def test_request_uri_is_refused(logged_in, client):
    url = authorize_url(
        client_id=client["client_id"], request_uri="https://client.test/request.jwt"
    )
    res = logged_in.get(url, status=400)
    assert res.json["error"] == "request_uri_not_supported"


def test_claims_member_of_the_request_object(logged_in, client):
    claims = request_claims(client, claims={"userinfo": {"email": None}})
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    code = callback_params(consent(logged_in, url))["code"]
    access_token = exchange_code(logged_in, client, code).json["access_token"]
    res = logged_in.get("/oauth/userinfo", headers=bearer(access_token))
    assert res.json["email"] == "alice@example.com"


def test_login_hint_of_the_request_object(testapp, client, other_persona):
    claims = request_claims(client, login_hint=MINIMAL_SUB)
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    res = testapp.get(url).follow()
    assert res.forms["select-persona"]["persona"].value == str(other_persona["id"])
