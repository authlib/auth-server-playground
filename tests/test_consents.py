import time
from types import SimpleNamespace
from urllib.parse import urlparse

from auth_server_playground.interaction import SESSION_AUTH_TIME
from auth_server_playground.interaction import PlaygroundSession
from auth_server_playground.models import Consent
from auth_server_playground.models import Persona
from auth_server_playground.models import db
from tests.conftest import make_client
from tests.test_authorization_code import code_url
from tests.utils import REDIRECT_URI
from tests.utils import consent


def consents_of(app, persona):
    with app.app_context():
        return [
            (item.client_id, item.scope)
            for item in Consent.query.filter_by(persona_id=persona["id"])
        ]


def test_accepting_stores_the_consent(app, logged_in, client, persona):
    consent(logged_in, code_url(client))
    assert consents_of(app, persona) == [("confidential-client", "profile")]


def test_stored_consent_skips_the_page(logged_in, client):
    consent(logged_in, code_url(client))
    res = logged_in.get(code_url(client, state="second"))
    assert res.location.startswith(REDIRECT_URI)


def test_wider_scope_shows_the_page_again(app, logged_in, persona):
    wide = make_client(
        app,
        client_id="wide-client",
        client_secret="wide-secret",
        metadata={
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "profile email",
        },
    )
    consent(logged_in, code_url(wide, scope="profile"))
    res = logged_in.get(code_url(wide, scope="profile email"))
    assert "consent" in res.forms
    consent(logged_in, code_url(wide, scope="profile email"))
    assert consents_of(app, persona) == [("wide-client", "profile email")]


def test_denying_stores_nothing(app, logged_in, client, persona):
    consent(logged_in, code_url(client), accept=False)
    assert consents_of(app, persona) == []


def test_persona_page_lists_and_revokes_consents(app, logged_in, client, persona):
    consent(logged_in, code_url(client))
    page = logged_in.get(f"/en/personas/{persona['id']}")
    assert "confidential-client" in page
    ids = [element["id"] for element in page.html.select("[id]")]
    assert len(ids) == len(set(ids))
    with app.app_context():
        consent_id = Consent.query.one().id
    button = page.html.select_one(f"#revoke-{consent_id} [type=submit]")
    assert button["aria-label"] == "Revoke the consent of confidential-client"
    page.forms[f"revoke-{consent_id}"].submit().follow()
    assert consents_of(app, persona) == []
    assert "consent" in logged_in.get(code_url(client)).forms


def test_revoke_needs_a_csrf_token(app, logged_in, client, persona):
    consent(logged_in, code_url(client))
    with app.app_context():
        consent_id = Consent.query.one().id
    logged_in.post(f"/en/personas/{persona['id']}/consents/{consent_id}/revoke")
    assert consents_of(app, persona) != []


def test_revoke_through_another_persona_is_refused(
    app, logged_in, client, persona, other_persona
):
    consent(logged_in, code_url(client))
    with app.app_context():
        consent_id = Consent.query.one().id
    logged_in.post(
        f"/en/personas/{other_persona['id']}/consents/{consent_id}/revoke", status=404
    )
    assert consents_of(app, persona) != []


def test_revoke_unknown_consent(logged_in, persona):
    logged_in.post(f"/en/personas/{persona['id']}/consents/999/revoke", status=404)


def test_deleting_the_client_deletes_its_consents(app, logged_in, client, persona):
    consent(logged_in, code_url(client))
    form = logged_in.get("/en/clients/confidential-client").forms["delete"]
    form.submit()
    assert consents_of(app, persona) == []


def test_deleting_the_persona_deletes_its_consents(app, logged_in, client, persona):
    consent(logged_in, code_url(client))
    form = logged_in.get(f"/en/personas/{persona['id']}").forms["delete"]
    form.submit()
    with app.app_context():
        assert Consent.query.count() == 0


def test_anonymous_request_goes_through_authlib_first(testapp, client):
    # The start time of the request is stored before the persona selector.
    res = testapp.get(code_url(client))
    assert urlparse(res.location).path == "/interaction/persona"
    with testapp.session_transaction() as session:
        assert PlaygroundSession.session_key in session


def interaction_time(app, persona, session, interaction, scope="profile"):
    with app.app_context():
        user = db.session.get(Persona, persona["id"])
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="confidential-client"), scope=scope
        )
        return PlaygroundSession(user, session).get_interaction_time(
            request, interaction
        )


def test_login_time_is_the_time_of_the_selection(app, logged_in, persona):
    with logged_in.session_transaction() as session:
        login_time = session[SESSION_AUTH_TIME]
        stored = dict(session)
    assert login_time < time.time() - 30
    assert interaction_time(app, persona, stored, "login") == login_time


def test_consent_time_is_the_time_of_the_covering_consent(
    app, logged_in, client, persona
):
    consent(logged_in, code_url(client))
    with app.app_context():
        granted_at = Consent.query.one().granted_at
    assert interaction_time(app, persona, {}, "consent") == granted_at
    assert interaction_time(app, persona, {}, "consent", "profile email") is None


def test_consent_time_is_unknown_without_a_consent(app, persona):
    assert interaction_time(app, persona, {}, "consent") is None


def test_unknown_interaction_has_no_time(app, persona):
    assert interaction_time(app, persona, {}, "create") is None
