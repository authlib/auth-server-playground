import faker.providers.internet
import pytest

from auth_server_playground.models import Persona
from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.personas import MINIMAL_SUB
from auth_server_playground.personas import RANDOM_LOCALES
from auth_server_playground.personas import random_locale_for
from auth_server_playground.personas import random_persona
from auth_server_playground.personas import render_avatar
from auth_server_playground.personas import username_from


@pytest.mark.parametrize("locale", RANDOM_LOCALES)
def test_random_persona(app, locale):
    with app.app_context():
        persona = random_persona(locale)
    claims = persona.claims
    assert persona.sub
    assert claims["locale"] == locale.replace("_", "-")
    assert claims["zoneinfo"] == RANDOM_LOCALES[locale]
    assert claims["email"] == f"{claims['preferred_username']}@example.com"
    assert claims["address"]["country"]
    assert claims["name"] == f"{claims['given_name']} {claims['family_name']}"
    assert claims["updated_at"]
    assert persona.picture_svg.startswith("<svg")


def test_random_username_is_unique(app, monkeypatch):
    monkeypatch.setattr(
        "auth_server_playground.personas.username_from", lambda *names: "alice"
    )
    with app.app_context():
        assert random_persona("en_US").claims["preferred_username"] != "alice"


def test_random_username_follows_the_name(app):
    with app.app_context():
        claims = random_persona("fr_FR").claims
    expected = username_from(claims["given_name"], claims["family_name"])
    assert claims["preferred_username"] == expected


def test_username_from():
    assert username_from("Élodie", "Le Gall") == "elegall"
    assert username_from("陽子", "佐藤") == ""


def test_username_from_another_script(app, monkeypatch):
    monkeypatch.setattr(
        faker.providers.internet.Provider, "user_name", lambda self: "yoko"
    )
    with app.app_context():
        assert random_persona("ja_JP").claims["preferred_username"] == "yoko"


def test_render_avatar():
    assert render_avatar().startswith("<svg")


def test_default_personas_pictures(app):
    with app.app_context():
        assert Persona.query.filter_by(sub=COMPLETE_SUB).one().picture_svg
        assert not Persona.query.filter_by(sub=MINIMAL_SUB).one().picture_svg


def test_random_locale_for():
    assert random_locale_for("fr") == "fr_FR"
    assert random_locale_for("xx") == "en_US"
