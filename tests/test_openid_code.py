import time
from urllib.parse import urlparse

import pytest

from auth_server_playground import keys
from auth_server_playground.models import Client
from auth_server_playground.models import SigningKey
from auth_server_playground.models import db
from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.personas import MINIMAL_SUB
from auth_server_playground.server import PlaygroundOpenIDCode
from tests.conftest import make_client
from tests.utils import CODE_VERIFIER
from tests.utils import REDIRECT_URI
from tests.utils import basic_auth
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import decode_id_token
from tests.utils import exchange_code
from tests.utils import oidc_url
from tests.utils import select_persona


def id_token_for(testapp, client, **params):
    """Run the code flow with consent, and return the decoded ID token."""
    code = callback_params(consent(testapp, oidc_url(client, **params)))["code"]
    return decode_id_token(
        testapp, exchange_code(testapp, client, code).json["id_token"]
    )


def test_id_token(app, logged_in, client):
    token = id_token_for(logged_in, client, nonce="n-0S6_WzA2Mj")
    claims = token.claims
    assert claims["iss"] == "http://localhost"
    assert claims["aud"] == ["confidential-client"]
    assert claims["sub"] == COMPLETE_SUB
    assert claims["nonce"] == "n-0S6_WzA2Mj"
    assert claims["exp"] - claims["iat"] == 3600
    assert time.time() - 70 < claims["auth_time"] < time.time() - 50
    assert claims["name"] == "Alice Martin"
    assert "email" not in claims
    with app.app_context():
        assert token.header["kid"] == keys.active_kid("RS256")


def test_id_token_lifetime_follows_the_setting(logged_in, client, configure):
    configure(settings={"id_token_lifetime": 60})
    claims = id_token_for(logged_in, client).claims
    assert claims["exp"] - claims["iat"] == 60


def test_rotation_changes_the_kid(app, logged_in, client):
    with app.app_context():
        kid = keys.rotate_key("RS256").kid
    assert id_token_for(logged_in, client).header["kid"] == kid


@pytest.mark.parametrize("alg", ["PS256", "ES256", "Ed25519"])
def test_client_signing_algorithm(app, logged_in, configure, alg):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", alg]})
    signed = make_client(
        app,
        client_id="signed-client",
        client_secret="signed-secret",
        metadata={
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "id_token_signed_response_alg": alg,
        },
    )
    token = id_token_for(logged_in, signed, scope="openid")
    assert token.header["alg"] == alg
    with app.app_context():
        assert token.header["kid"] == keys.active_kid(alg)


def test_header_has_no_kid_without_an_active_key(app, client):
    """Task 7 covers the real flow of a client with a deleted algorithm key."""
    with app.app_context():
        SigningKey.query.filter_by(alg="RS256", active=True).update({"active": False})
        db.session.commit()
        stored = Client.query.filter_by(client_id=client["client_id"]).one()
        header = PlaygroundOpenIDCode("", 3600).get_encode_header(stored)
    assert header == {"alg": "RS256"}


def test_nonce_of_a_pending_code_is_refused(logged_in, client):
    consent(logged_in, oidc_url(client, nonce="same"))
    res = logged_in.get(oidc_url(client, nonce="same", state="second"))
    params = callback_params(res)
    assert params["error"] == "invalid_request"
    assert params["error_description"] == "Replay attack"


def test_issuer_follows_the_setting(logged_in, client, configure):
    configure(metadata={"issuer": "https://issuer.test"})
    assert id_token_for(logged_in, client).claims["iss"] == "https://issuer.test"


@pytest.mark.parametrize("proxy_fix", [True])
def test_issuer_behind_a_proxy_matches_the_discovery(logged_in, client):
    prefix = {"X-Forwarded-Prefix": "/auth"}
    code = callback_params(consent(logged_in, oidc_url(client)))["code"]
    res = logged_in.post(
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": CODE_VERIFIER,
        },
        headers={**basic_auth(client), **prefix},
    )
    issuer = logged_in.get("/.well-known/openid-configuration", headers=prefix)
    claims = decode_id_token(logged_in, res.json["id_token"]).claims
    assert issuer.json["issuer"] == "http://localhost/auth"
    assert claims["iss"] == issuer.json["issuer"]


def test_prompt_none_without_persona(testapp, client):
    res = testapp.get(oidc_url(client, prompt="none"))
    assert callback_params(res)["error"] == "login_required"


def test_prompt_none_without_consent(logged_in, client):
    res = logged_in.get(oidc_url(client, prompt="none"))
    assert callback_params(res)["error"] == "consent_required"


def test_prompt_none_with_consent(logged_in, client):
    consent(logged_in, oidc_url(client))
    res = logged_in.get(oidc_url(client, prompt="none", state="silent"))
    assert "code" in callback_params(res)


def selector_path(res):
    return urlparse(res.location).path


def test_prompt_consent_without_stored_consent(logged_in, client):
    res = logged_in.get(oidc_url(client, prompt="consent"))
    assert "consent" in res.forms


def test_prompt_consent_asks_again(logged_in, client, monkeypatch):
    # Authlib compares whole seconds: a consent of this second would count as
    # given after the new request started.
    now = time.time()
    with monkeypatch.context() as patch:
        patch.setattr(time, "time", lambda: now - 60)
        consent(logged_in, oidc_url(client))
    res = logged_in.get(oidc_url(client, prompt="consent", state="again"))
    assert "consent" in res.forms


def test_prompt_login_asks_for_a_persona_again(logged_in, client, persona):
    consent(logged_in, oidc_url(client))
    url = oidc_url(client, prompt="login")
    assert selector_path(logged_in.get(url)) == "/interaction/persona"
    select_persona(logged_in, persona)
    # The selection is a new login: the request goes on without the selector.
    res = logged_in.get(url)
    code = callback_params(res)["code"]
    claims = decode_id_token(
        logged_in, exchange_code(logged_in, client, code).json["id_token"]
    ).claims
    assert claims["auth_time"] >= time.time() - 5


def test_prompt_select_account(logged_in, client):
    res = logged_in.get(oidc_url(client, prompt="select_account"))
    assert selector_path(res) == "/interaction/persona"


@pytest.mark.parametrize("max_age", ["0", "30"])
def test_old_login_with_max_age(logged_in, client, max_age):
    res = logged_in.get(oidc_url(client, max_age=max_age))
    assert selector_path(res) == "/interaction/persona"


def test_recent_login_with_max_age(logged_in, client):
    res = logged_in.get(oidc_url(client, max_age="3600"))
    assert "consent" in res.forms


@pytest.mark.parametrize(
    ("default_max_age", "expected"), [(30, "persona"), (3600, "consent")]
)
def test_default_max_age_of_the_client(app, logged_in, default_max_age, expected):
    signed = make_client(
        app,
        client_id="aged-client",
        client_secret="aged-secret",
        metadata={
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "default_max_age": default_max_age,
        },
    )
    res = logged_in.get(oidc_url(signed, scope="openid"))
    if expected == "persona":
        assert selector_path(res) == "/interaction/persona"
    else:
        assert "consent" in res.forms


def test_id_token_hint(logged_in, client):
    consent(logged_in, oidc_url(client))
    hint = exchange_code(
        logged_in,
        client,
        callback_params(logged_in.get(oidc_url(client, state="a")))["code"],
    ).json["id_token"]
    res = logged_in.get(oidc_url(client, prompt="none", id_token_hint=hint, state="b"))
    assert "code" in callback_params(res)


def test_id_token_hint_signed_by_a_retired_key(app, logged_in, client):
    consent(logged_in, oidc_url(client))
    hint = exchange_code(
        logged_in,
        client,
        callback_params(logged_in.get(oidc_url(client, state="a")))["code"],
    ).json["id_token"]
    with app.app_context():
        keys.rotate_key("RS256")
    res = logged_in.get(oidc_url(client, prompt="none", id_token_hint=hint, state="b"))
    assert "code" in callback_params(res)


def test_id_token_hint_of_another_persona(logged_in, client, other_persona):
    consent(logged_in, oidc_url(client))
    hint = exchange_code(
        logged_in,
        client,
        callback_params(logged_in.get(oidc_url(client, state="a")))["code"],
    ).json["id_token"]
    select_persona(logged_in, other_persona)
    res = logged_in.get(oidc_url(client, prompt="none", id_token_hint=hint, state="b"))
    assert callback_params(res)["error"] == "login_required"


def test_invalid_id_token_hint(logged_in, client):
    res = logged_in.get(oidc_url(client, id_token_hint="not-a-token"))
    assert callback_params(res)["error"] == "invalid_request"


@pytest.mark.parametrize("hint", ["bob@example.com", "Bob@Example.COM", MINIMAL_SUB])
def test_login_hint_selects_the_persona(testapp, client, other_persona, hint):
    res = testapp.get(oidc_url(client, login_hint=hint)).follow()
    assert res.forms["select-persona"]["persona"].value == str(other_persona["id"])


@pytest.mark.parametrize("hint", [None, "nobody@example.com"])
def test_selector_selects_the_current_persona(logged_in, client, persona, hint):
    res = logged_in.get(oidc_url(client, prompt="login", login_hint=hint)).follow()
    assert res.forms["select-persona"]["persona"].value == str(persona["id"])


def test_login_hint_for_another_persona_opens_the_selector(
    logged_in, client, other_persona
):
    res = logged_in.get(oidc_url(client, login_hint=MINIMAL_SUB))
    assert selector_path(res) == "/interaction/persona"
    res = res.follow()
    assert res.forms["select-persona"]["persona"].value == str(other_persona["id"])


def test_selection_after_the_login_hint_goes_on(logged_in, client):
    res = logged_in.get(oidc_url(client, login_hint=MINIMAL_SUB)).follow()
    res = res.forms["select-persona"].submit().follow()
    assert "consent" in res.forms


@pytest.mark.parametrize("hint", [COMPLETE_SUB, "nobody@example.com"])
def test_login_hint_without_another_persona_skips_the_selector(logged_in, client, hint):
    res = logged_in.get(oidc_url(client, login_hint=hint))
    assert "consent" in res.forms


def test_prompt_none_with_a_login_hint_for_another_persona(logged_in, client):
    consent(logged_in, oidc_url(client))
    url = oidc_url(client, prompt="none", login_hint=MINIMAL_SUB, state="silent")
    res = logged_in.get(url)
    assert callback_params(res)["error"] == "account_selection_required"


def test_ui_locales_choose_the_language(testapp, client):
    res = testapp.get(oidc_url(client, ui_locales="de fr-CA")).follow()
    assert '<html lang="fr"' in res.text


def test_ui_locales_on_the_consent_page(logged_in, client):
    res = logged_in.get(oidc_url(client, ui_locales="fr"))
    assert '<html lang="fr"' in res.text


@pytest.mark.parametrize(
    "param", [{"display": "popup"}, {"acr_values": "1 2"}, {"claims_locales": "fr"}]
)
def test_ignored_parameters(logged_in, client, param):
    assert "consent" in logged_in.get(oidc_url(client, **param)).forms


def test_no_id_token_without_openid(logged_in, client):
    code = callback_params(consent(logged_in, oidc_url(client, scope="profile")))[
        "code"
    ]
    assert "id_token" not in exchange_code(logged_in, client, code).json


def test_openid_is_refused_when_disabled(logged_in, client, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    res = logged_in.get(oidc_url(client))
    assert callback_params(res)["error"] == "invalid_scope"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="Authlib signs with an algorithm that the server no longer publishes.",
)
def test_disabled_client_algorithm_is_refused(app, logged_in, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "ES256"]})
    signed = make_client(
        app,
        client_id="es-client",
        client_secret="es-secret",
        metadata={
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "id_token_signed_response_alg": "ES256",
        },
    )
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256"]})
    code = callback_params(consent(logged_in, oidc_url(signed, scope="openid")))["code"]
    res = exchange_code(logged_in, signed, code, status="*")
    assert "id_token" not in res.json


@pytest.mark.xfail(
    strict=True,
    raises=ValueError,
    reason="Authlib raises ValueError, not an OAuth error, when no key has the client algorithm.",
)
def test_deleted_client_algorithm_key(app, logged_in, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "ES256"]})
    signed = make_client(
        app,
        client_id="es-client",
        client_secret="es-secret",
        metadata={
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid",
            "id_token_signed_response_alg": "ES256",
        },
    )
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256"]})
    with app.app_context():
        for key in keys.all_keys():
            if key.alg == "ES256":
                keys.delete_key(key, ["RS256"])
    code = callback_params(consent(logged_in, oidc_url(signed, scope="openid")))["code"]
    assert exchange_code(logged_in, signed, code, status="*").status_int == 400
