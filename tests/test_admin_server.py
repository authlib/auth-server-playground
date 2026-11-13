import pytest

from auth_server_playground.store import settings_row


def text(res, selector):
    return res.html.select_one(selector).get_text(" ", strip=True)


def revision(app):
    with app.app_context():
        return settings_row().revision


def test_root_redirects_to_the_browser_language(testapp):
    assert testapp.get("/").location.endswith("/en/")
    res = testapp.get("/", headers={"Accept-Language": "fr"})
    assert res.location.endswith("/fr/")


def test_unknown_language(testapp):
    testapp.get("/xx/", status=404)


def test_home_shows_the_endpoints(testapp):
    res = testapp.get("/en/")
    assert "http://localhost/.well-known/oauth-authorization-server" in res
    assert 'data-copy="http://localhost/oauth/token"' in res


def test_home_counts(testapp, client, public_client):
    res = testapp.get("/en/")
    assert text(res, "#client-count") == "2"
    assert text(res, "#persona-count") == "2"


def test_home_warns_about_unsupported_client_values(testapp, client):
    res = testapp.get("/en/")
    warning = text(res, '[data-type="warning"]')
    assert client["client_id"] in warning
    assert "password" in warning


def test_home_shows_the_persona(logged_in):
    res = logged_in.get("/en/")
    assert "Alice Martin" in text(res, "header")


def test_save_server_settings(app, testapp):
    before = revision(app)
    form = testapp.get("/en/server").forms["server"]
    form["grant_types_supported"] = ["authorization_code", "implicit"]
    form["access_token_lifetime"] = "60"
    res = form.submit().follow()
    assert 'data-type="success"' in res
    assert revision(app) == before + 1
    metadata = testapp.get("/.well-known/oauth-authorization-server").json
    assert metadata["grant_types_supported"] == ["authorization_code", "implicit"]
    assert metadata["response_types_supported"] == ["code", "token"]


def test_server_form_shows_the_stored_settings(testapp, configure):
    configure(settings={"refresh_token_lifetime": 600})
    form = testapp.get("/en/server").forms["server"]
    assert form["refresh_token_lifetime"].value == "600"
    assert form["scopes_supported"].value == "profile email"


def test_invalid_lifetime_is_refused(app, testapp):
    before = revision(app)
    form = testapp.get("/en/server").forms["server"]
    form["access_token_lifetime"] = "0"
    res = form.submit()
    assert res.status_int == 200
    assert revision(app) == before


@pytest.mark.parametrize("insecure_transport", [False])
def test_document_error_goes_to_its_field(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["issuer"] = "http://server.test"
    res = form.submit()
    issuer = text(res, "#wrap-issuer")
    assert "https" in issuer
    assert "authorization_endpoint" not in issuer


def test_document_error_without_field(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["token_endpoint_auth_methods_supported"] = ["none"]
    res = form.submit()
    assert "confidential" in text(res, "#wrap-token_endpoint_auth_methods_supported")


def test_preview(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["revocation_enabled"] = False
    res = testapp.post("/en/server/preview", form.submit_fields())
    assert "revocation_endpoint" not in res
    assert "token_endpoint" in res


def test_preview_shows_form_errors(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["access_token_lifetime"] = "0"
    res = testapp.post("/en/server/preview", form.submit_fields())
    assert 'role="alert"' in res


def test_preview_shows_document_errors(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["token_endpoint_auth_methods_supported"] = ["none"]
    res = testapp.post("/en/server/preview", form.submit_fields())
    assert 'role="alert"' in res
    assert "token_endpoint_auth_methods_supported" in res


def test_preview_without_scopes(testapp):
    form = testapp.get("/en/server").forms["server"]
    fields = [(k, v) for k, v in form.submit_fields() if k != "scopes_supported"]
    res = testapp.post("/en/server/preview", fields)
    assert "token_endpoint" in res


def test_metadata_order(testapp):
    res = testapp.get("/.well-known/oauth-authorization-server")
    assert list(res.json)[:2] == ["issuer", "authorization_endpoint"]


def test_root_keeps_the_session_language(testapp):
    testapp.get("/fr/")
    assert testapp.get("/").location.endswith("/fr/")


def test_restore_defaults(testapp, configure):
    configure(settings={"access_token_lifetime": 60})
    testapp.get("/en/server").forms["defaults"].submit().follow()
    form = testapp.get("/en/server").forms["server"]
    assert form["access_token_lifetime"].value == "3600"


def test_restore_defaults_needs_a_csrf_token(testapp, configure):
    configure(settings={"access_token_lifetime": 60})
    testapp.post("/en/server/defaults")
    form = testapp.get("/en/server").forms["server"]
    assert form["access_token_lifetime"].value == "60"
