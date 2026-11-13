from auth_server_playground.models import Client


def test_home_lists_the_clients(testapp, client):
    res = testapp.get("/")
    assert client["client_id"] in res


def test_home_shows_the_persona(logged_in):
    res = logged_in.get("/")
    assert "Alice Martin" in res


def _fill_client_form(form, auth_method):
    form["client_name"] = "My client"
    form["client_uri"] = "http://client.test"
    form["scope"] = "profile"
    form["redirect_uri"] = "http://client.test/callback\nhttp://client.test/other"
    form["grant_type"] = "authorization_code\nrefresh_token"
    form["response_type"] = "code"
    form["token_endpoint_auth_method"] = auth_method


def test_create_confidential_client(app, testapp):
    form = testapp.get("/create_client").forms[0]
    _fill_client_form(form, "client_secret_basic")
    res = form.submit()
    assert res.location.endswith("/")

    with app.app_context():
        client = Client.query.one()
        assert client.client_secret
        assert client.client_name == "My client"
        assert client.redirect_uris == [
            "http://client.test/callback",
            "http://client.test/other",
        ]
        assert client.grant_types == ["authorization_code", "refresh_token"]
        assert client.token_endpoint_auth_method == "client_secret_basic"

    assert "My client" in res.follow()


def test_create_public_client(app, testapp):
    form = testapp.get("/create_client").forms[0]
    _fill_client_form(form, "none")
    form.submit()

    with app.app_context():
        client = Client.query.one()
        assert client.client_secret == ""
        assert client.token_endpoint_auth_method == "none"
