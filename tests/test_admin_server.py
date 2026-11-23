import pytest

from auth_server_playground import keys
from auth_server_playground.store import current_document
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
    assert res.html.select_one('input.copy-value[value="http://localhost/oauth/token"]')


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
    assert form["scopes_supported"].value == "openid profile email address phone"


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


def test_document_error_without_a_field_goes_on_top(testapp):
    """Authlib refuses an empty response_types_supported, see RFC 8414 §2."""
    form = testapp.get("/en/server").forms["server"]
    form["grant_types_supported"] = ["client_credentials"]
    form["scopes_supported"] = "profile"
    res = form.submit()
    assert "response_types_supported" in text(res, "#server")


def test_copy_fields_have_a_label(testapp, client):
    for url in ("/en/", f"/en/clients/{client['client_id']}"):
        res = testapp.get(url)
        fields = res.html.select("input.copy-value")
        assert fields
        for field in fields:
            assert res.html.select_one(f'label[for="{field["id"]}"]')


def test_copy_button(testapp):
    res = testapp.get("/en/")
    field = res.html.select_one("#token_endpoint-value")
    group = field.parent
    button = group.select_one("button[data-copy]")
    assert group["aria-labelledby"] == "token_endpoint-value-label"
    assert button["aria-label"] == "Copy token_endpoint"
    assert {span.get("data-when") for span in button.select("span")} == {
        None,
        "copied",
        "failed",
    }
    assert group.find_next_sibling()["role"] == "status"


def test_server_form_sets_the_openid_settings(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["id_token_signing_alg_values_supported"] = ["RS256", "Ed25519"]
    form["id_token_lifetime"] = "600"
    form.submit().follow()
    with app.app_context():
        document = current_document()
        assert document["metadata"]["id_token_signing_alg_values_supported"] == [
            "RS256",
            "Ed25519",
        ]
        assert document["settings"]["id_token_lifetime"] == 600
        assert keys.active_kid("Ed25519") is not None


def test_server_form_sets_the_userinfo_algorithms(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["userinfo_signing_alg_values_supported"] = ["RS256", "ES256"]
    form.submit().follow()
    with app.app_context():
        document = current_document()
        assert document["metadata"]["userinfo_signing_alg_values_supported"] == [
            "RS256",
            "ES256",
        ]
        assert keys.active_kid("ES256") is not None


def test_server_form_answers_in_json_only(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["userinfo_signing_alg_values_supported"] = []
    form.submit().follow()
    with app.app_context():
        document = current_document()
        assert document["metadata"]["userinfo_signing_alg_values_supported"] == []


def test_server_form_shows_the_rs256_error(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["id_token_signing_alg_values_supported"] = ["ES256"]
    res = form.submit()
    assert "RS256" in text(res, "#id_token_signing_alg_values_supported-error")


def test_home_shows_the_discovery_url(testapp):
    res = testapp.get("/en/")
    assert "http://localhost/.well-known/openid-configuration" in res


def test_home_hides_the_discovery_url_without_openid(testapp, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    res = testapp.get("/en/")
    assert "openid-configuration" not in res


def stored_settings(app):
    with app.app_context():
        return current_document()["settings"]


def test_token_mode_generates_a_token(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["registration"] = "token"
    res = form.submit().follow()
    token = stored_settings(app)["initial_access_token"]
    assert token
    assert res.html.select_one(f'input.copy-value[value="{token}"]')


def test_open_mode_keeps_the_token(app, testapp, configure):
    configure(settings={"registration": "token", "initial_access_token": "kept"})
    form = testapp.get("/en/server").forms["server"]
    form["registration"] = "open"
    res = form.submit().follow()
    assert stored_settings(app)["initial_access_token"] == "kept"
    assert "kept" not in res


def test_renew_the_initial_access_token(app, testapp, configure):
    configure(settings={"registration": "token", "initial_access_token": "old"})
    res = testapp.get("/en/server").forms["renew"].submit().follow()
    assert 'data-type="success"' in res
    assert stored_settings(app)["initial_access_token"] not in ("old", None)


def test_renew_needs_a_csrf_token(app, testapp, configure):
    configure(settings={"registration": "token", "initial_access_token": "old"})
    testapp.post("/en/server/initial-access-token")
    assert stored_settings(app)["initial_access_token"] == "old"


def test_save_registration_settings(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["registration"] = "disabled"
    form["outbound_private_addresses"] = False
    form["require_signed_request_object"] = True
    form["request_object_signing_alg_values_supported"] = ["RS256"]
    form.submit().follow()
    with app.app_context():
        document = current_document()

    assert document["settings"]["registration"] == "disabled"
    assert document["settings"]["outbound_private_addresses"] is False
    assert document["metadata"]["require_signed_request_object"] is True
    assert document["metadata"]["request_object_signing_alg_values_supported"] == [
        "RS256"
    ]


def test_preview_in_token_mode(testapp):
    form = testapp.get("/en/server").forms["server"]
    form["registration"] = "token"
    res = testapp.post("/en/server/preview", form.submit_fields())
    assert 'role="alert"' not in res
    assert "token_endpoint" in res


def test_save_the_remaining_metadata(app, testapp):
    form = testapp.get("/en/server").forms["server"]
    form["revocation_endpoint_auth_methods_supported"] = ["client_secret_basic"]
    form["prompt_values_supported"] = ["none", "login"]
    form["ui_locales_supported"] = ["fr"]
    form["claims_parameter_supported"] = False
    form["request_parameter_supported"] = False
    form.submit().follow()
    with app.app_context():
        metadata = current_document()["metadata"]

    assert metadata["revocation_endpoint_auth_methods_supported"] == [
        "client_secret_basic"
    ]
    assert metadata["prompt_values_supported"] == ["none", "login"]
    assert metadata["ui_locales_supported"] == ["fr"]
    assert metadata["claims_parameter_supported"] is False
    assert metadata["request_parameter_supported"] is False
