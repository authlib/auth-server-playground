import pytest

from auth_server_playground.models import Persona
from auth_server_playground.models import Token
from auth_server_playground.models import db
from tests.utils import password_token


def text(res, selector):
    return res.html.select_one(selector).get_text(" ", strip=True)


def stored(app, sub):
    with app.app_context():
        persona = Persona.query.filter_by(sub=sub).one()
        return {"id": persona.id, "claims": persona.claims, "svg": persona.picture_svg}


def test_personas_list(testapp, persona, other_persona):
    res = testapp.get("/en/personas")
    assert persona["sub"] in res
    assert other_persona["sub"] in res
    assert res.html.select_one(f'img[src$="/personas/{persona["id"]}/picture.svg"]')


def test_create_persona(app, testapp):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["sub"] = "carol-sub"
    form["preferred_username"] = "carol"
    form["email"] = "carol@example.com"
    form["email_verified"] = True
    form["birthdate"] = "1985-04-02"
    form["zoneinfo"] = "Europe/Paris"
    form["address_locality"] = "Lyon"
    form["extra_claims"] = '{"department": "R&D"}'
    res = form.submit()
    claims = stored(app, "carol-sub")["claims"]
    assert res.location.endswith(f"/en/personas/{stored(app, 'carol-sub')['id']}")
    assert claims["preferred_username"] == "carol"
    assert claims["email_verified"] is True
    assert claims["birthdate"] == "1985-04-02"
    assert claims["zoneinfo"] == "Europe/Paris"
    assert claims["address"] == {"locality": "Lyon"}
    assert claims["department"] == "R&D"
    assert claims["updated_at"]
    assert "name" not in claims
    assert "phone_number_verified" not in claims
    assert stored(app, "carol-sub")["svg"].startswith("<svg")


def test_generated_sub(app, testapp):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["preferred_username"] = "dave"
    form.submit()
    with app.app_context():
        persona = Persona.query.filter(
            Persona.claims["preferred_username"].as_string() == "dave"
        ).one()
        assert persona.sub


def test_username_must_be_unique(testapp, persona):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["preferred_username"] = persona["preferred_username"]
    assert "already" in text(form.submit(), "#wrap-preferred_username")


def test_sub_must_be_unique(testapp, persona):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["sub"] = persona["sub"]
    assert "already" in text(form.submit(), "#wrap-sub")


@pytest.mark.parametrize("value", ["[1, 2]", "{not json", '{"email": "x@example.com"}'])
def test_invalid_extra_claims(app, testapp, value):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["extra_claims"] = value
    res = form.submit()
    assert res.status_int == 200
    assert text(res, "#extra_claims-error")
    with app.app_context():
        assert Persona.query.count() == 2


def test_edit_persona(app, testapp, persona):
    before = stored(app, persona["sub"])
    form = testapp.get(f"/en/personas/{persona['id']}").forms["persona"]
    assert form["address_locality"].value == "Paris"
    form["nickname"] = "Al"
    form.submit()
    after = stored(app, persona["sub"])
    assert after["claims"]["nickname"] == "Al"
    assert after["claims"]["updated_at"] >= before["claims"]["updated_at"]
    assert after["claims"]["address"] == before["claims"]["address"]
    assert after["svg"] == before["svg"]


def test_edit_keeps_the_extra_claims(app, testapp, persona):
    with app.app_context():
        row = db.session.get(Persona, persona["id"])
        row.claims = {**row.claims, "department": "R&D"}
        db.session.commit()
    form = testapp.get(f"/en/personas/{persona['id']}").forms["persona"]
    assert "department" in form["extra_claims"].value
    form.submit()
    assert stored(app, persona["sub"])["claims"]["department"] == "R&D"


def test_random_persona_from_admin(app, testapp):
    form = testapp.get("/en/personas").forms["random"]
    form["random-locale"] = "fr_FR"
    res = form.submit()
    with app.app_context():
        persona = Persona.query.order_by(Persona.id.desc()).first()
        assert persona.claims["locale"] == "fr-FR"
    assert res.location.endswith(f"/en/personas/{persona.id}")


def test_redraw_avatar(app, testapp, persona):
    before = stored(app, persona["sub"])["svg"]
    testapp.get(f"/en/personas/{persona['id']}").forms["avatar"].submit()
    assert stored(app, persona["sub"])["svg"] != before


def test_picture(testapp, persona):
    res = testapp.get(f"/personas/{persona['id']}/picture.svg")
    assert res.content_type == "image/svg+xml"
    assert "default-src 'none'" in res.headers["Content-Security-Policy"]


def test_no_picture(testapp, other_persona):
    testapp.get(f"/personas/{other_persona['id']}/picture.svg", status=404)


def test_unknown_persona(testapp):
    testapp.get("/en/personas/999", status=404)
    testapp.get("/personas/999/picture.svg", status=404)


def test_delete_persona_with_its_tokens(app, testapp, client, persona, legacy_grants):
    password_token(testapp, client, persona)
    res = testapp.get(f"/en/personas/{persona['id']}").forms["delete"].submit()
    assert res.location.endswith("/en/personas")
    with app.app_context():
        assert db.session.get(Persona, persona["id"]) is None
        assert Token.query.filter_by(persona_id=persona["id"]).count() == 0


def test_delete_needs_a_csrf_token(app, testapp, persona):
    testapp.post(f"/en/personas/{persona['id']}/delete")
    with app.app_context():
        assert db.session.get(Persona, persona["id"])


def test_persona_page_has_unique_ids(testapp, persona):
    res = testapp.get(f"/en/personas/{persona['id']}")
    ids = [element["id"] for element in res.html.select("[id]")]
    assert len(ids) == len(set(ids))


def test_random_persona_from_the_selector(app, testapp):
    page = testapp.get("/interaction/persona?next=/en/")
    res = page.forms["random"].submit()
    assert res.location == "/en/"
    with app.app_context():
        assert Persona.query.count() == 3
    assert "Forget persona" in testapp.get("/en/")


def test_random_persona_follows_the_language(app, testapp):
    page = testapp.get("/interaction/persona", headers={"Accept-Language": "fr"})
    page.forms["random"].submit(headers={"Accept-Language": "fr"})
    with app.app_context():
        persona = Persona.query.order_by(Persona.id.desc()).first()
        assert persona.claims["locale"] == "fr-FR"


def test_random_persona_needs_a_csrf_token(testapp):
    testapp.post("/interaction/persona/random", status=400)


def test_selector_shows_the_avatars(testapp, persona):
    res = testapp.get("/interaction/persona")
    assert res.html.select_one(f'img[src$="/personas/{persona["id"]}/picture.svg"]')


def test_edit_a_minimal_persona(app, testapp, other_persona):
    form = testapp.get(f"/en/personas/{other_persona['id']}").forms["persona"]
    assert form["birthdate"].value == ""
    form.submit()
    claims = stored(app, other_persona["sub"])["claims"]
    assert "birthdate" not in claims
    assert "address" not in claims


def test_random_persona_needs_a_csrf_token_in_admin(app, testapp):
    res = testapp.post("/en/personas/random", {"random-locale": "fr_FR"})
    assert res.location.endswith("/en/personas")
    with app.app_context():
        assert Persona.query.count() == 2


def test_redraw_avatar_needs_a_csrf_token(app, testapp, persona):
    before = stored(app, persona["sub"])["svg"]
    testapp.post(f"/en/personas/{persona['id']}/avatar")
    assert stored(app, persona["sub"])["svg"] == before


def test_picture_claim_replaces_the_avatar(app, testapp, persona):
    form = testapp.get(f"/en/personas/{persona['id']}").forms["persona"]
    form["picture"] = "https://alice.example/photo.png"
    form.submit()
    res = testapp.get("/en/personas")
    assert res.html.select_one('img[src="https://alice.example/photo.png"]')


def test_subject_with_a_slash(app, testapp, persona):
    form = testapp.get(f"/en/personas/{persona['id']}").forms["persona"]
    form["sub"] = "users/42"
    form.submit()
    res = testapp.get("/en/personas")
    url = res.html.select_one(f'img[src$="/personas/{persona["id"]}/picture.svg"]')
    testapp.get(url["src"])


@pytest.mark.parametrize("value", ["x" * 256, "émile"])
def test_invalid_subject(testapp, value):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["sub"] = value
    assert "ASCII" in text(form.submit(), "#wrap-sub")


@pytest.mark.parametrize("value", ["1990", "0000-12-10", "1990-12-10"])
def test_partial_birthdate(app, testapp, value):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["sub"] = "born"
    form["birthdate"] = value
    form.submit()
    assert stored(app, "born")["claims"]["birthdate"] == value
    page = testapp.get(f"/en/personas/{stored(app, 'born')['id']}")
    assert page.forms["persona"]["birthdate"].value == value


def test_invalid_birthdate(testapp):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["birthdate"] = "10/12/1990"
    assert text(form.submit(), "#birthdate-error")


def test_blank_extra_claims(app, testapp):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["sub"] = "blank"
    form["extra_claims"] = "  \n "
    form.submit()
    assert stored(app, "blank")


def test_edit_keeps_unknown_address_keys(app, testapp, persona):
    with app.app_context():
        row = db.session.get(Persona, persona["id"])
        row.claims = {**row.claims, "address": {"locality": "Paris", "floor": "3"}}
        db.session.commit()
    testapp.get(f"/en/personas/{persona['id']}").forms["persona"].submit()
    address = stored(app, persona["sub"])["claims"]["address"]
    assert address == {"locality": "Paris", "floor": "3"}


def test_no_redraw_with_a_picture_claim(testapp, persona):
    form = testapp.get(f"/en/personas/{persona['id']}").forms["persona"]
    form["picture"] = "https://alice.example/photo.png"
    form.submit()
    assert "avatar" not in testapp.get(f"/en/personas/{persona['id']}").forms


def test_redraw_updates_updated_at(app, testapp, persona):
    with app.app_context():
        row = db.session.get(Persona, persona["id"])
        row.claims = {**row.claims, "updated_at": 1}
        db.session.commit()
    testapp.get(f"/en/personas/{persona['id']}").forms["avatar"].submit()
    assert stored(app, persona["sub"])["claims"]["updated_at"] > 1


def test_random_form_follows_the_language(testapp):
    form = testapp.get("/fr/personas").forms["random"]
    assert form["random-locale"].value == "fr_FR"


def test_birthdate_that_does_not_exist(testapp):
    form = testapp.get("/en/personas/new").forms["persona"]
    form["birthdate"] = "1990-02-30"
    assert text(form.submit(), "#birthdate-error")


def test_edit_keeps_unknown_zoneinfo_and_locale(app, testapp, persona):
    with app.app_context():
        row = db.session.get(Persona, persona["id"])
        row.claims = {**row.claims, "zoneinfo": "Etc/Unknown", "locale": "en-us"}
        db.session.commit()
    testapp.get(f"/en/personas/{persona['id']}").forms["persona"].submit()
    claims = stored(app, persona["sub"])["claims"]
    assert claims["zoneinfo"] == "Etc/Unknown"
    assert claims["locale"] == "en-us"
