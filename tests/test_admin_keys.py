from auth_server_playground import keys
from auth_server_playground.models import SigningKey
from auth_server_playground.models import db
from tests.utils import csrf_token


def active(app, alg):
    with app.app_context():
        return keys.active_kid(alg)


def test_keys_page_lists_the_keys(app, testapp):
    res = testapp.get("/en/keys")
    assert active(app, "RS256") in res
    assert "http://localhost/oauth/jwks" in res


def test_rotate(app, testapp):
    old = active(app, "RS256")
    res = testapp.get("/en/keys").forms["rotate-RS256"].submit().follow()
    assert active(app, "RS256") != old
    states = {
        row.select_one(".copy-value")["value"]: row.select("td")[3].get_text(strip=True)
        for row in res.html.select("tbody tr")
    }
    assert states[old] == "Retired"
    assert states[active(app, "RS256")] == "Active"
    with app.app_context():
        assert db.session.get(SigningKey, old).active is False


def test_rotate_a_disabled_algorithm(testapp):
    testapp.post(
        "/en/keys/ES256/rotate", {"csrf_token": csrf_token(testapp)}, status=404
    )


def test_delete_a_retired_key(app, testapp):
    old = active(app, "RS256")
    testapp.get("/en/keys").forms["rotate-RS256"].submit()
    testapp.get("/en/keys").forms[f"delete-{old}"].submit().follow()
    with app.app_context():
        assert db.session.get(SigningKey, old) is None


def test_active_key_cannot_be_deleted(app, testapp):
    kid = active(app, "RS256")
    res = testapp.get("/en/keys")
    assert f"delete-{kid}" not in res.forms
    # The page offers no delete form for this key. The CSRF token is the same
    # for all the forms of a session, so a request can still be forged.
    token = res.forms["rotate-RS256"]["rotate-RS256-csrf_token"].value
    res = testapp.post(
        f"/en/keys/{kid}/delete", {f"delete-{kid}-csrf_token": token}
    ).follow()
    assert "Rotate it first" in res
    assert active(app, "RS256") == kid


def test_delete_unknown_key(testapp):
    testapp.post(
        "/en/keys/unknown/delete", {"csrf_token": csrf_token(testapp)}, status=404
    )


def test_keys_page_has_unique_ids(app, testapp):
    testapp.get("/en/keys").forms["rotate-RS256"].submit()
    res = testapp.get("/en/keys")
    ids = [element["id"] for element in res.html.select("[id]")]
    assert len(ids) == len(set(ids))


def test_key_of_a_disabled_algorithm_can_be_deleted(app, testapp, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "ES256"]})
    kid = active(app, "ES256")
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256"]})
    res = testapp.get("/en/keys")
    assert "<mark>disabled</mark>" in res
    res.forms[f"delete-{kid}"].submit().follow()
    with app.app_context():
        assert db.session.get(SigningKey, kid) is None


def test_userinfo_algorithm_gets_a_key(app, testapp, configure):
    configure(metadata={"userinfo_signing_alg_values_supported": ["ES256"]})
    kid = active(app, "ES256")
    assert kid is not None
    res = testapp.get("/en/keys")
    assert "Rotate ES256" in res
    assert f"delete-{kid}" not in res.forms


def test_active_key_of_a_userinfo_algorithm_cannot_be_deleted(app, testapp, configure):
    configure(metadata={"userinfo_signing_alg_values_supported": ["ES256"]})
    kid = active(app, "ES256")
    res = testapp.get("/en/keys")
    assert f"delete-{kid}" not in res.forms
    token = res.forms["rotate-ES256"]["rotate-ES256-csrf_token"].value
    res = testapp.post(
        f"/en/keys/{kid}/delete", {f"delete-{kid}-csrf_token": token}
    ).follow()
    assert "This key is active. Rotate it first." in res
    with app.app_context():
        assert db.session.get(SigningKey, kid) is not None


def test_row_buttons_have_distinct_names(app, testapp):
    old = active(app, "RS256")
    testapp.get("/en/keys").forms["rotate-RS256"].submit()
    res = testapp.get("/en/keys")
    delete = res.html.select_one(f"#delete-{old} input[type=submit]")
    assert delete["aria-label"] == f"Delete the RS256 key {old}"
    labels = [button["aria-label"] for button in res.html.select("[data-copy]")]
    assert f"Copy the RS256 key ID {old}" in labels
    assert len(labels) == len(set(labels))
