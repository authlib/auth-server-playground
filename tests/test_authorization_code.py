from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from tests.utils import CODE_VERIFIER
from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import exchange_code


def code_url(client, **params):
    return authorize_url(
        **{
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": REDIRECT_URI,
            "scope": "profile",
            "state": "xyz",
            "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
            "code_challenge_method": "S256",
            **params,
        }
    )


def test_authorization_asks_for_a_persona(testapp, client):
    url = code_url(client)
    res = testapp.get(url)
    assert urlparse(res.location).path == "/interaction/persona"

    next_url = urlparse(parse_qs(urlparse(res.location).query)["next"][0])
    assert next_url.path == "/oauth/authorize"
    assert parse_qs(next_url.query) == parse_qs(urlparse(url).query)


def test_consent_page(logged_in, client, persona):
    res = logged_in.get(code_url(client))
    assert "Test client" in res
    assert "profile" in res
    assert "Alice Martin" in res


def test_authorization_code_flow(logged_in, client, persona):
    params = callback_params(consent(logged_in, code_url(client)))
    assert params["state"] == "xyz"

    res = logged_in.post(
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": CODE_VERIFIER,
        },
        headers=basic_auth(client),
    )
    assert res.json["token_type"] == "Bearer"
    assert res.json["scope"] == "profile"
    assert res.json["refresh_token"]

    res = logged_in.get("/api/resource", headers=bearer(res.json["access_token"]))
    assert res.json["sub"] == persona["sub"]


def test_consent_denied(logged_in, client):
    res = consent(logged_in, code_url(client), accept=False)
    params = callback_params(res)
    assert params["error"] == "access_denied"
    assert params["state"] == "xyz"


def test_authorization_code_is_single_use(logged_in, client):
    params = callback_params(consent(logged_in, code_url(client)))
    data = {
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": REDIRECT_URI,
        "code_verifier": CODE_VERIFIER,
    }
    logged_in.post("/oauth/token", data, headers=basic_auth(client))

    res = logged_in.post("/oauth/token", data, headers=basic_auth(client), status=400)
    assert res.json["error"] == "invalid_grant"


def code_token(logged_in, client):
    """Run the code flow and return the code and the token."""
    code = callback_params(consent(logged_in, code_url(client)))["code"]
    return code, exchange_code(logged_in, client, code).json


def refresh(logged_in, client, refresh_token, *, status=200):
    return logged_in.post(
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers=basic_auth(client),
        status=status,
    )


def reuse_code(logged_in, client, code):
    res = exchange_code(logged_in, client, code, status=400)
    assert res.json["error"] == "invalid_grant"


def test_code_reuse_revokes_the_access_token(logged_in, client):
    code, token = code_token(logged_in, client)
    logged_in.get("/api/resource", headers=bearer(token["access_token"]))

    reuse_code(logged_in, client, code)

    logged_in.get("/api/resource", headers=bearer(token["access_token"]), status=401)


def test_code_reuse_revokes_the_refresh_token(logged_in, client):
    code, token = code_token(logged_in, client)

    reuse_code(logged_in, client, code)

    res = refresh(logged_in, client, token["refresh_token"], status=400)
    assert res.json["error"] == "invalid_grant"


def test_code_reuse_revokes_the_refreshed_tokens(logged_in, client):
    code, token = code_token(logged_in, client)
    refreshed = refresh(logged_in, client, token["refresh_token"]).json
    logged_in.get("/api/resource", headers=bearer(refreshed["access_token"]))

    reuse_code(logged_in, client, code)

    logged_in.get(
        "/api/resource", headers=bearer(refreshed["access_token"]), status=401
    )
    refresh(logged_in, client, refreshed["refresh_token"], status=400)


def test_unknown_code_revokes_nothing(logged_in, client):
    _, token = code_token(logged_in, client)

    exchange_code(logged_in, client, "unknown", status=400)

    logged_in.get("/api/resource", headers=bearer(token["access_token"]))
    refresh(logged_in, client, token["refresh_token"])


def test_pkce_is_required_for_public_clients(logged_in, public_client):
    url = code_url(public_client, code_challenge=None, code_challenge_method=None)
    params = callback_params(logged_in.get(url))
    assert params["error"] == "invalid_request"
    assert params["state"] == "xyz"


def test_public_clients_must_send_the_code_verifier(logged_in, public_client):
    params = callback_params(consent(logged_in, code_url(public_client)))

    res = logged_in.post(
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "client_id": public_client["client_id"],
            "code": params["code"],
            "redirect_uri": REDIRECT_URI,
        },
        status=400,
    )
    assert res.json["error"] == "invalid_request"


def test_wrong_code_verifier(logged_in, client):
    params = callback_params(consent(logged_in, code_url(client)))
    res = logged_in.post(
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": generate_token(48),
        },
        headers=basic_auth(client),
        status=400,
    )
    assert res.json["error"] == "invalid_grant"


@pytest.mark.parametrize("client_id", ["unknown", None])
@pytest.mark.parametrize(("scopes", "status"), [(None, 404), (["profile"], 400)])
def test_unknown_client(logged_in, configure, client_id, scopes, status):
    # With OpenID Connect, the request object extension of Authlib checks the
    # client first. It answers 404, where the grant answers 400.
    if scopes:
        configure(metadata={"scopes_supported": scopes})

    url = code_url({"client_id": "unknown"}, client_id=client_id)
    res = logged_in.get(url, status=status)
    assert res.json["error"] == "invalid_client"
