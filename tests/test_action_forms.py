import pytest

from auth_server_playground.keys import all_keys
from auth_server_playground.models import Client
from auth_server_playground.models import Consent
from auth_server_playground.models import Persona
from auth_server_playground.store import current_document
from tests.test_authorization_code import code_url
from tests.utils import consent

EXPIRED = "The page expired. Reload it and try again."


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


@pytest.mark.parametrize(
    "action",
    [
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
    ],
)
def test_action_without_a_csrf_token_says_the_page_expired(
    app, testapp, targets, action
):
    url, back = targets[action]
    before = state(app)
    res = testapp.post(url)
    assert res.location.endswith(back)
    page = res.follow()
    assert EXPIRED in page.html.select_one('[data-type="error"]').text
    assert not page.html.select('[data-type="success"]')
    assert state(app) == before


def test_regenerate_without_a_secret_says_so(app, testapp, public_client):
    url = f"/en/clients/{public_client['client_id']}"
    form = testapp.get(url).forms["delete"]
    res = testapp.post(
        f"{url}/secret", {"regenerate-csrf_token": form["delete-csrf_token"].value}
    )
    assert res.location.endswith(url)
    page = res.follow()
    assert (
        "This client has no secret." in page.html.select_one('[data-type="error"]').text
    )
    assert not page.html.select('[data-type="success"]')
    with app.app_context():
        assert (
            Client.query.filter_by(client_id="public-client").one().client_secret == ""
        )
