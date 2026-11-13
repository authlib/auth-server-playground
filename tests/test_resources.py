from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import client_credentials_token


def test_resource_needs_a_token(testapp):
    res = testapp.get("/api/resource", status=401)
    assert res.headers["WWW-Authenticate"] == "Bearer"


def test_resource_rejects_an_unknown_token(testapp):
    res = testapp.get("/api/resource", headers=bearer("unknown"), status=401)
    assert res.json["error"] == "invalid_token"


def test_revocation(testapp, client):
    token = client_credentials_token(testapp, client).json
    testapp.get("/api/resource", headers=bearer(token["access_token"]))

    testapp.post(
        "/oauth/revoke",
        {"token": token["access_token"], "token_type_hint": "access_token"},
        headers=basic_auth(client),
    )

    testapp.get("/api/resource", headers=bearer(token["access_token"]), status=401)
