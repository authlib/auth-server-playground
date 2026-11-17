import json

from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import decode_id_token
from tests.utils import exchange_code
from tests.utils import oidc_url

EXTRA_CLAIMS = "Claims requested beyond the scopes:"


def tokens_for(testapp, client, claims_request, *, scope="openid"):
    """Run the code flow with a claims parameter, and return the token response."""
    url = oidc_url(client, scope=scope, claims=json.dumps(claims_request))
    code = callback_params(consent(testapp, url))["code"]
    return exchange_code(testapp, client, code).json


def userinfo(testapp, access_token):
    return testapp.get("/oauth/userinfo", headers=bearer(access_token)).json


def listed_extra_claims(page):
    """Return the claims that the consent page lists beyond the scopes."""
    title = page.html.find("p", string=EXTRA_CLAIMS)
    return [code.get_text() for code in title.find_next_sibling("ul").select("code")]


def test_userinfo_member_adds_a_claim(logged_in, client):
    tokens = tokens_for(logged_in, client, {"userinfo": {"email": None}})
    info = userinfo(logged_in, tokens["access_token"])
    assert info["email"] == "alice@example.com"
    assert "name" not in info


def test_id_token_member_adds_a_claim(logged_in, client):
    tokens = tokens_for(logged_in, client, {"id_token": {"name": None}})
    claims = decode_id_token(logged_in, tokens["id_token"]).claims
    assert claims["name"] == "Alice Martin"
    assert "name" not in userinfo(logged_in, tokens["access_token"])


def test_claims_request_survives_a_refresh(logged_in, client):
    tokens = tokens_for(logged_in, client, {"userinfo": {"email": None}})
    res = logged_in.post(
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        headers=basic_auth(client),
    )
    info = userinfo(logged_in, res.json["access_token"])
    assert info["email"] == "alice@example.com"


def test_invalid_claims_parameter(logged_in, client):
    res = logged_in.get(oidc_url(client, claims="not json"))
    assert callback_params(res)["error"] == "invalid_request"


def test_consent_page_lists_the_claims_beyond_the_scopes(logged_in, client):
    claims_request = {
        "userinfo": {"email": None, "name": None},
        "id_token": {"acr": None},
    }
    page = logged_in.get(oidc_url(client, claims=json.dumps(claims_request)))
    assert listed_extra_claims(page) == ["email"]


def test_consent_page_without_claims_beyond_the_scopes(logged_in, client):
    page = logged_in.get(oidc_url(client))
    assert EXTRA_CLAIMS not in page.text


def test_stored_consent_for_the_scope_is_enough(logged_in, client):
    consent(logged_in, oidc_url(client))
    claims_request = {"userinfo": {"email": None}}
    res = logged_in.get(oidc_url(client, claims=json.dumps(claims_request)))
    assert "code" in callback_params(res)


def test_claims_parameter_disabled(logged_in, client, configure):
    configure(metadata={"claims_parameter_supported": False})
    tokens = tokens_for(logged_in, client, {"userinfo": {"email": None}})
    assert "email" not in userinfo(logged_in, tokens["access_token"])
