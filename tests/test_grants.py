from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import password_token


def test_password_grant(testapp, client, persona):
    res = password_token(testapp, client, persona)
    assert res.json["token_type"] == "Bearer"
    assert res.json["refresh_token"]

    res = testapp.get("/api/me", headers=bearer(res.json["access_token"]))
    assert res.json["sub"] == persona["sub"]


def test_password_grant_accepts_any_password(testapp, client, persona):
    password_token(testapp, client, persona, password="")


def test_password_grant_unknown_user(testapp, client, persona):
    res = password_token(testapp, client, persona, username="unknown", status=400)
    assert res.json["error"] == "invalid_request"


def test_client_credentials_grant(testapp, client):
    res = testapp.post(
        "/oauth/token",
        {"grant_type": "client_credentials", "scope": "profile"},
        headers=basic_auth(client),
    )
    assert res.json["token_type"] == "Bearer"
    assert "refresh_token" not in res.json


def test_wrong_client_secret(testapp, client):
    res = testapp.post(
        "/oauth/token",
        {"grant_type": "client_credentials"},
        headers=basic_auth({**client, "client_secret": "wrong"}),
        status=401,
    )
    assert res.json["error"] == "invalid_client"


def test_refresh_token_grant(testapp, client, persona):
    first = password_token(testapp, client, persona).json

    res = testapp.post(
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        headers=basic_auth(client),
    )
    second = res.json
    assert second["access_token"] != first["access_token"]

    testapp.get("/api/me", headers=bearer(second["access_token"]))
    testapp.get("/api/me", headers=bearer(first["access_token"]), status=401)

    res = testapp.post(
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        headers=basic_auth(client),
        status=400,
    )
    assert res.json["error"] == "invalid_grant"


def test_implicit_grant(logged_in, public_client, persona):
    url = authorize_url(
        response_type="token",
        client_id=public_client["client_id"],
        redirect_uri=REDIRECT_URI,
        scope="profile",
        state="xyz",
    )
    params = callback_params(consent(logged_in, url), fragment=True)
    assert params["state"] == "xyz"
    assert "refresh_token" not in params

    res = logged_in.get("/api/me", headers=bearer(params["access_token"]))
    assert res.json["sub"] == persona["sub"]
