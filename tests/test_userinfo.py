from auth_server_playground.personas import COMPLETE_SUB
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import exchange_code
from tests.utils import oidc_url


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


def test_userinfo_needs_a_token(testapp):
    testapp.get("/oauth/userinfo", status=401)


def test_userinfo_without_openid(testapp, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    testapp.get("/oauth/userinfo", status=404)
