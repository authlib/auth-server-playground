import pytest

from auth_server_playground.models import Client
from auth_server_playground.models import Token
from auth_server_playground.models import db
from tests.utils import client_credentials_token


def text(res, selector):
    return res.html.select_one(selector).get_text(" ", strip=True)


def new_client_form(testapp, **values):
    form = testapp.get("/en/clients/new").forms["client"]
    form["client_name"] = "Demo"
    form["redirect_uris"] = "https://client.test/callback"
    form["grant_types"] = ["authorization_code", "refresh_token", "client_credentials"]
    form["response_types"] = ["code"]
    form["scope"] = "profile"
    form["token_endpoint_auth_method"] = "client_secret_basic"
    for key, value in values.items():
        form[key] = value
    return form


def stored(app, client_id):
    with app.app_context():
        client = Client.query.filter_by(client_id=client_id).one()
        return {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "client_metadata": client.client_metadata,
        }


def test_create_client_with_a_chosen_id(app, testapp):
    res = new_client_form(testapp, client_id="my-client").submit()
    assert res.location.endswith("/en/clients/my-client")
    client = stored(app, "my-client")
    assert client["client_secret"]
    assert client["client_metadata"]["client_name"] == "Demo"
    assert client["client_metadata"]["redirect_uris"] == [
        "https://client.test/callback"
    ]
    assert client_credentials_token(testapp, client).json["access_token"]


def test_create_client_with_a_random_id(app, testapp):
    res = new_client_form(testapp).submit().follow()
    with app.app_context():
        client = Client.query.one()
    assert client.client_id
    assert client.client_id in res


def test_public_client_has_no_secret(app, testapp):
    new_client_form(
        testapp, client_id="public", token_endpoint_auth_method="none"
    ).submit()
    assert stored(app, "public")["client_secret"] == ""


def test_duplicate_client_id_is_refused(testapp, client):
    res = new_client_form(testapp, client_id=client["client_id"]).submit()
    assert res.status_int == 200
    assert "already" in text(res, "#wrap-client_id")


def test_redirect_uris_must_be_urls(testapp):
    res = new_client_form(testapp, redirect_uris="not a url").submit()
    assert res.status_int == 200
    assert "not a url" in text(res, "#wrap-redirect_uris")


def test_new_client_needs_a_csrf_token(app, testapp):
    testapp.post("/en/clients/new", {"client_name": "Demo"}, status=200)
    with app.app_context():
        assert Client.query.count() == 0


def test_edit_client(app, testapp, client):
    form = testapp.get(f"/en/clients/{client['client_id']}").forms["client"]
    form["client_name"] = "Renamed"
    form["contacts"] = "dev@client.test\nops@client.test"
    form.submit()
    metadata = stored(app, client["client_id"])["client_metadata"]
    assert metadata["client_name"] == "Renamed"
    assert metadata["contacts"] == ["dev@client.test", "ops@client.test"]


def test_edit_client_keeps_its_secret(app, testapp, client):
    testapp.get(f"/en/clients/{client['client_id']}").forms["client"].submit()
    assert stored(app, client["client_id"])["client_secret"] == client["client_secret"]


def test_switch_to_a_confidential_method_creates_a_secret(app, testapp, public_client):
    form = testapp.get(f"/en/clients/{public_client['client_id']}").forms["client"]
    form["token_endpoint_auth_method"] = "client_secret_post"
    form.submit()
    assert stored(app, public_client["client_id"])["client_secret"]


def test_switch_to_a_public_client_drops_the_secret(app, testapp, client):
    form = testapp.get(f"/en/clients/{client['client_id']}").forms["client"]
    form["token_endpoint_auth_method"] = "none"
    form.submit()
    assert stored(app, client["client_id"])["client_secret"] == ""


def test_regenerate_secret(app, testapp, client):
    page = testapp.get(f"/en/clients/{client['client_id']}")
    page.forms["regenerate"].submit()
    assert stored(app, client["client_id"])["client_secret"] != client["client_secret"]
    client_credentials_token(testapp, client, status=401)


def test_public_client_has_no_regenerate_button(testapp, public_client):
    page = testapp.get(f"/en/clients/{public_client['client_id']}")
    assert "regenerate" not in page.forms


def test_delete_client_with_its_tokens(app, testapp, client):
    client_credentials_token(testapp, client)
    page = testapp.get(f"/en/clients/{client['client_id']}")
    res = page.forms["delete"].submit()
    assert res.location.endswith("/en/clients")
    with app.app_context():
        assert Client.query.filter_by(client_id=client["client_id"]).count() == 0
        assert Token.query.filter_by(client_id=client["client_id"]).count() == 0


def test_delete_needs_a_csrf_token(app, testapp, client):
    testapp.post(f"/en/clients/{client['client_id']}/delete")
    with app.app_context():
        assert Client.query.filter_by(client_id=client["client_id"]).count() == 1


def test_unsupported_values_are_marked(testapp, client):
    res = testapp.get(f"/en/clients/{client['client_id']}")
    assert "not supported" in text(res, 'label[for="grant_types-2"]')  # password
    assert "not supported" not in text(res, 'label[for="grant_types-0"]')
    password = res.html.select_one("#grant_types-2")
    assert password.has_attr("checked")
    assert not password.has_attr("disabled")


def test_clients_list(testapp, client, public_client):
    res = testapp.get("/en/clients")
    rows = text(res, "table")
    assert client["client_id"] in rows
    assert public_client["client_id"] in rows
    assert "password" in text(res, '[data-type="warning"]')


def test_unknown_client(testapp):
    testapp.get("/en/clients/unknown", status=404)


def test_regenerate_without_a_secret(app, testapp, public_client):
    page = testapp.get(f"/en/clients/{public_client['client_id']}")
    form = page.forms["delete"]
    testapp.post(
        f"/en/clients/{public_client['client_id']}/secret",
        {"regenerate-csrf_token": form["delete-csrf_token"].value},
    )
    assert stored(app, public_client["client_id"])["client_secret"] == ""


def test_home_without_warning_for_a_supported_client(testapp):
    new_client_form(testapp, client_id="fine").submit()
    res = testapp.get("/en/")
    assert not res.html.select('[data-type="warning"]')


@pytest.mark.parametrize("value", ["a/b", "new", "..", "x" * 49, "with space"])
def test_invalid_client_id(app, testapp, value):
    res = new_client_form(testapp, client_id=value).submit()
    assert res.status_int == 200
    with app.app_context():
        assert Client.query.count() == 0


def test_client_id_is_stripped(app, testapp):
    new_client_form(testapp, client_id="  spaced  ").submit()
    assert stored(app, "spaced")


@pytest.mark.parametrize(
    "value",
    [
        "https://",
        "https://client.test/cb#frag",
        "ftp://client.test/cb",
        "http://[::1/cb",
    ],
)
def test_invalid_redirect_uri(testapp, value):
    res = new_client_form(testapp, redirect_uris=value).submit()
    assert res.status_int == 200
    assert value in text(res, "#wrap-redirect_uris")


def test_invalid_logo_uri(testapp):
    res = new_client_form(testapp, logo_uri="javascript:alert(1)").submit()
    assert res.status_int == 200
    assert text(res, "#logo_uri-error")


def set_metadata(app, client_id, **metadata):
    with app.app_context():
        client = Client.query.filter_by(client_id=client_id).one()
        client.set_client_metadata({**client.client_metadata, **metadata})
        db.session.commit()


def test_edit_keeps_the_metadata_without_field(app, testapp, client):
    set_metadata(app, client["client_id"], jwks_uri="https://client.test/jwks")
    testapp.get(f"/en/clients/{client['client_id']}").forms["client"].submit()
    metadata = stored(app, client["client_id"])["client_metadata"]
    assert metadata["jwks_uri"] == "https://client.test/jwks"


def test_edit_removes_a_cleared_field(app, testapp, client):
    set_metadata(app, client["client_id"], logo_uri="https://client.test/logo.png")
    form = testapp.get(f"/en/clients/{client['client_id']}").forms["client"]
    form["logo_uri"] = ""
    form.submit()
    assert "logo_uri" not in stored(app, client["client_id"])["client_metadata"]


def test_edit_keeps_unknown_values(app, testapp, client):
    set_metadata(
        app,
        client["client_id"],
        token_endpoint_auth_method="private_key_jwt",
        grant_types=[
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ],
    )
    res = testapp.get(f"/en/clients/{client['client_id']}")
    assert "not supported" in text(res, "#wrap-token_endpoint_auth_method")
    res.forms["client"].submit()
    metadata = stored(app, client["client_id"])["client_metadata"]
    assert metadata["token_endpoint_auth_method"] == "private_key_jwt"
    assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in metadata["grant_types"]


def test_client_page_has_unique_ids(testapp, client):
    res = testapp.get(f"/en/clients/{client['client_id']}")
    ids = [element["id"] for element in res.html.select("[id]")]
    assert len(ids) == len(set(ids))


def test_navigation_marks_the_clients_section(testapp, client):
    res = testapp.get(f"/en/clients/{client['client_id']}")
    assert text(res, 'nav [aria-current="page"]') == "Clients"
