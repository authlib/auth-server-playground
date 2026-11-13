from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest

from auth_server_playground.models import Persona
from auth_server_playground.models import db
from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import callback_params
from tests.utils import consent


def code_url(client):
    # A PKCE challenge, so that the URL stays valid when PKCE is required for
    # all clients. It is the example of RFC 7636 Appendix B.
    return authorize_url(
        response_type="code",
        client_id=client["client_id"],
        redirect_uri=REDIRECT_URI,
        scope="profile",
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method="S256",
    )


def select_form(testapp, url, persona):
    form = testapp.get(url).forms["select-persona"]
    form["persona"] = str(persona["id"])
    return form


def test_selected_persona_comes_back_to_the_authorization(testapp, client, persona):
    url = code_url(client)
    res = select_form(testapp, testapp.get(url).location, persona).submit()
    assert res.location == url


def test_selection_without_next_goes_home(testapp, persona):
    res = select_form(testapp, "/interaction/persona", persona).submit()
    assert urlparse(res.location).path == "/en/"


@pytest.mark.parametrize(
    "next_url",
    [
        "https://evil.test/",
        "//evil.test/",
        "/\\evil.test/",
        "/\t/evil.test/",
        "/\n/evil.test/",
        " //evil.test/",
        "evil.test",
    ],
)
def test_external_next_is_ignored(testapp, persona, next_url):
    url = "/interaction/persona?" + urlencode({"next": next_url})
    res = select_form(testapp, url, persona).submit()
    location = urlparse(res.location)
    assert location.netloc in ("", "localhost")
    assert location.path == "/en/"


def test_selector_lists_the_personas(testapp, other_persona):
    res = testapp.get("/interaction/persona")
    assert "Alice Martin" in res
    assert other_persona["preferred_username"] in res


def test_selection_is_required(testapp):
    form = testapp.get("/interaction/persona").forms["select-persona"]
    res = form.submit()
    assert res.status_int == 200
    assert "select-persona" in res


def test_consent_page_shows_the_persona(logged_in, client):
    res = logged_in.get(code_url(client))
    assert "Alice Martin" in res


def test_consent_denied(logged_in, client):
    res = consent(logged_in, code_url(client), accept=False)
    assert callback_params(res)["error"] == "access_denied"


def test_consent_without_csrf_token_is_refused(logged_in, client):
    logged_in.post(code_url(client), {"accept": "Accept"}, status=400)


def test_forget_persona(logged_in, client):
    res = logged_in.get("/interaction/forget")
    assert urlparse(res.location).path == "/en/"
    res = logged_in.get(code_url(client))
    assert urlparse(res.location).path == "/interaction/persona"


def test_forget_without_persona(testapp):
    res = testapp.get("/interaction/forget")
    assert urlparse(res.location).path == "/en/"


def test_deleted_persona_counts_as_no_persona(app, logged_in, client, persona):
    with app.app_context():
        db.session.delete(db.session.get(Persona, persona["id"]))
        db.session.commit()
    res = logged_in.get(code_url(client))
    assert urlparse(res.location).path == "/interaction/persona"


def test_consent_for_another_persona_is_refused(logged_in, client, other_persona):
    form = logged_in.get(code_url(client)).forms["consent"]
    select_form(logged_in, "/interaction/persona", other_persona).submit()
    res = form.submit("accept")
    assert res.status_int == 200
    assert "consent" in res.forms


def test_consent_shows_the_authorization_request(logged_in, client):
    res = logged_in.get(code_url(client))
    details = res.html.select_one("details").get_text(" ", strip=True)
    assert "redirect_uri" in details
    assert REDIRECT_URI in details


def test_consent_request_leaves_out_the_form_fields(logged_in, client, other_persona):
    form = logged_in.get(code_url(client)).forms["consent"]
    select_form(logged_in, "/interaction/persona", other_persona).submit()
    res = form.submit("accept")
    details = res.html.select_one("details").get_text(" ", strip=True)
    assert "redirect_uri" in details
    assert "csrf_token" not in details
    assert "persona_id" not in details


def test_selector_names_the_client(testapp, client):
    res = testapp.get(code_url(client)).follow()
    assert "Test client" in res.html.select_one("main").get_text()


def test_selector_does_not_name_an_unknown_client(testapp):
    url = authorize_url(response_type="code", client_id="Your Bank")
    res = testapp.get(url).follow()
    assert "Your Bank" not in res.html.select_one("main").get_text()


def test_selector_without_a_client(testapp):
    res = testapp.get("/interaction/persona?next=/en/")
    assert "asks you" not in res.html.select_one("main").get_text()


def test_selector_without_a_client_id(testapp):
    url = "/interaction/persona?" + urlencode(
        {"next": authorize_url(response_type="code")}
    )
    res = testapp.get(url)
    assert "asks you" not in res.html.select_one("main").get_text()
