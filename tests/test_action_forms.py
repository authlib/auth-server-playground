from urllib.parse import parse_qs
from urllib.parse import parse_qsl
from urllib.parse import urlsplit

import pytest

from auth_server_playground.keys import all_keys
from auth_server_playground.models import Client
from auth_server_playground.models import Consent
from auth_server_playground.models import Persona
from auth_server_playground.store import current_document
from tests.test_authorization_code import code_url
from tests.utils import consent
from tests.utils import csrf_token

INVALID_TOKEN = (
    "The form token is not valid. Check that cookies are allowed, then reload the page."
)
WRONG_LOCALE = "Choose a locale from the list."


def state(app):
    """Return what the action forms can change."""
    with app.app_context():
        return {
            "document": current_document(),
            "keys": sorted(key.kid for key in all_keys()),
            "clients": sorted(
                (c.client_id, c.client_secret) for c in Client.query.all()
            ),
            "personas": sorted(
                (p.id, p.picture_svg, str(p.claims)) for p in Persona.query.all()
            ),
            "consents": sorted(c.id for c in Consent.query.all()),
        }


@pytest.fixture
def targets(app, logged_in, client, dynamic_client, persona):
    """Return the URL of each action, and the page it redirects to."""
    consent(logged_in, code_url(client))
    with app.app_context():
        consent_id = Consent.query.one().id
        kid = next(key.kid for key in all_keys() if key.alg == "RS256")

    pid = persona["id"]
    cid = client["client_id"]
    return {
        "renew": ("/en/server/initial-access-token", "/en/server"),
        "defaults": ("/en/server/defaults", "/en/server"),
        "rotate": ("/en/keys/RS256/rotate", "/en/keys"),
        "remove_key": (f"/en/keys/{kid}/delete", "/en/keys"),
        "remove_dynamic": ("/en/dynamic-clients/delete", "/en/clients"),
        "regenerate": (f"/en/clients/{cid}/secret", f"/en/clients/{cid}"),
        "remove_client": (f"/en/clients/{cid}/delete", f"/en/clients/{cid}"),
        "random": ("/en/personas/random", "/en/personas"),
        "avatar": (f"/en/personas/{pid}/avatar", f"/en/personas/{pid}"),
        "revoke": (
            f"/en/personas/{pid}/consents/{consent_id}/revoke",
            f"/en/personas/{pid}",
        ),
        "remove_persona": (f"/en/personas/{pid}/delete", f"/en/personas/{pid}"),
    }


ACTIONS = [
    "renew",
    "defaults",
    "rotate",
    "remove_key",
    "remove_dynamic",
    "regenerate",
    "remove_client",
    "random",
    "avatar",
    "revoke",
    "remove_persona",
]


def error_message(page):
    return page.html.select_one('[data-type="error"]').text


@pytest.mark.parametrize("action", ACTIONS)
def test_action_with_a_bad_token_goes_back_to_the_referrer(
    app, testapp, targets, action
):
    url, back = targets[action]
    before = state(app)
    res = testapp.post(url, headers={"Referer": f"http://localhost{back}"})
    assert res.location.endswith(back)
    page = res.follow()
    assert INVALID_TOKEN in error_message(page)
    assert not page.html.select('[data-type="success"]')
    assert state(app) == before


def test_random_persona_of_the_selector_with_a_bad_token(app, testapp):
    before = state(app)
    res = testapp.post(
        "/interaction/persona/random",
        headers={"Referer": "http://localhost/interaction/persona?next=/en/"},
    )
    assert res.location.endswith("/interaction/persona?next=/en/")
    assert INVALID_TOKEN in error_message(res.follow())
    assert state(app) == before


@pytest.mark.parametrize(
    "headers", [{}, {"Referer": "http://other.test/en/server"}], ids=["none", "foreign"]
)
def test_action_without_a_usable_referrer_goes_to_the_admin_home(
    testapp, targets, headers
):
    res = testapp.post(targets["defaults"][0], headers=headers)
    assert res.location.endswith("/en/")
    assert INVALID_TOKEN in error_message(res.follow())


def test_admin_home_follows_the_language_of_the_url(testapp):
    res = testapp.post("/fr/server/defaults")
    assert res.location.endswith("/fr/")


@pytest.mark.parametrize(
    "url",
    [
        "/en/server",
        "/en/clients/new",
        "/en/personas/new",
        "/en/snapshot",
        "/interaction/persona?next=/en/",
    ],
)
def test_form_with_a_bad_token_shows_again(app, testapp, persona, url):
    before = state(app)
    res = testapp.post(url, {"client_name": "Demo"})
    assert res.status_int == 303
    assert res.location == f"http://localhost{url}"
    assert INVALID_TOKEN in error_message(res.follow())
    assert state(app) == before


def test_consent_with_a_bad_token_shows_the_consent_page_again(app, logged_in, client):
    url = code_url(client)
    res = logged_in.post(url, {"accept": "Accept"})
    assert res.status_int == 303
    location = urlsplit(res.location)
    assert location.path == "/oauth/authorize"
    assert parse_qs(location.query) == parse_qs(urlsplit(url).query)
    page = res.follow()
    assert INVALID_TOKEN in error_message(page)
    assert "consent" in page.forms
    with app.app_context():
        assert Consent.query.count() == 0


def test_consent_with_a_wrong_persona_field_is_refused(logged_in, client):
    form = logged_in.get(code_url(client)).forms["consent"]
    form["persona_id"].force_value("not a number")
    form.submit("accept", status=400)


def test_authorization_request_by_post_needs_no_token(logged_in, client):
    """A client can send the request by POST (OIDC Core §3.1.2.1)."""
    params = dict(parse_qsl(urlsplit(code_url(client)).query))
    res = logged_in.post("/oauth/authorize", params, status=303)
    assert res.location.startswith("/oauth/authorize?")
    assert "consent" in res.follow().forms


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("post", "/oauth/token", 400),
        ("post", "/oauth/revoke", 401),
        ("post", "/oauth/register", 201),
        ("get", "/oauth/register/unknown", 401),
        ("put", "/oauth/register/unknown", 401),
        ("delete", "/oauth/register/unknown", 401),
        ("post", "/oauth/userinfo", 401),
    ],
)
def test_oauth_api_needs_no_csrf_token(testapp, method, path, status):
    if path == "/oauth/register":
        res = testapp.post_json(
            path, {"redirect_uris": ["http://client.test/callback"]}
        )
    else:
        res = getattr(testapp, method)(path, expect_errors=True)

    assert res.status_int == status
    assert res.content_type == "application/json"


def test_token_never_expires(app, make_app):
    assert app.config["WTF_CSRF_TIME_LIMIT"] is None
    assert make_app(WTF_CSRF_TIME_LIMIT=60).config["WTF_CSRF_TIME_LIMIT"] == 60


def test_admin_random_persona_with_a_bad_locale(app, testapp):
    before = state(app)
    form = testapp.get("/en/personas").forms["random"]
    form["random-locale"].force_value("xx_XX")
    page = form.submit().follow()
    assert WRONG_LOCALE in error_message(page)
    assert INVALID_TOKEN not in page.text
    assert state(app) == before


def test_confirm_import_without_a_snapshot_says_so(testapp):
    page = testapp.get("/en/snapshot")
    token = page.forms["import"]["csrf_token"].value
    res = testapp.post("/en/snapshot/confirm", {"csrf_token": token})
    assert "This snapshot cannot be imported" in error_message(res.follow())


def test_preview_with_a_bad_token_shows_the_error(testapp):
    """The preview changes nothing: its form checks the token itself."""
    form = testapp.get("/en/server").forms["server"]
    form["csrf_token"] = "bad"
    res = testapp.post("/en/server/preview", form.submit_fields())
    assert res.status_int == 200
    assert "<code>csrf_token</code>" in res.html.select_one('[role="alert"]').decode()


@pytest.mark.parametrize("proxy_fix", [True])
def test_referrer_out_of_the_app_root_is_not_followed(testapp, targets):
    res = testapp.post(
        targets["defaults"][0],
        headers={"X-Forwarded-Prefix": "/auth", "Referer": "http://localhost/other/"},
    )
    assert res.location.endswith("/auth/en/")


@pytest.mark.parametrize("proxy_fix", [True])
def test_https_post_needs_no_referrer(app, testapp):
    res = testapp.post(
        "/en/server/defaults",
        {"csrf_token": csrf_token(testapp)},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert res.location.endswith("/en/server")
    assert res.follow().html.select('[data-type="success"]')
