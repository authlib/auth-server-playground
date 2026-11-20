import pytest

from auth_server_playground.models import Client
from auth_server_playground.models import Token
from tests.test_registration import REGISTRATION
from tests.test_registration import register
from tests.utils import bearer
from tests.utils import client_credentials_token


@pytest.fixture
def registered(testapp):
    return register(testapp, {**REGISTRATION, "contacts": ["dev@client.test"]}).json


def configuration_url(client):
    return f"/oauth/register/{client['client_id']}"


def headers_of(client):
    return bearer(client["registration_access_token"])


def test_read_the_registration(testapp, registered):
    body = testapp.get(
        configuration_url(registered), headers=headers_of(registered)
    ).json
    assert body["client_id"] == registered["client_id"]
    assert body["client_secret"] == registered["client_secret"]
    assert body["contacts"] == ["dev@client.test"]
    assert body["registration_access_token"] == registered["registration_access_token"]
    assert body["registration_client_uri"].endswith(configuration_url(registered))


def test_read_needs_the_token(testapp, registered):
    testapp.get(configuration_url(registered), status=401)
    res = testapp.get(
        configuration_url(registered), headers=bearer("wrong"), status=401
    )
    assert res.json["error"] == "invalid_token"


def test_token_of_another_client(testapp, registered):
    other = register(testapp).json
    res = testapp.get(
        configuration_url(other), headers=headers_of(registered), status=401
    )
    assert res.json["error"] == "invalid_token"


def test_admin_clients_are_out_of_reach(testapp, registered, client):
    res = testapp.get(
        configuration_url(client), headers=headers_of(registered), status=401
    )
    assert res.json["error"] == "invalid_token"


def test_replace_the_metadata(testapp, registered):
    res = testapp.put_json(
        configuration_url(registered),
        {
            **REGISTRATION,
            "client_id": registered["client_id"],
            "client_name": "Renamed",
        },
        headers=headers_of(registered),
    )
    assert res.json["client_name"] == "Renamed"
    assert "contacts" not in res.json
    assert (
        res.json["registration_access_token"] == registered["registration_access_token"]
    )


def test_replace_without_scope_keeps_no_default(testapp, registered):
    res = testapp.put_json(
        configuration_url(registered),
        {
            "redirect_uris": REGISTRATION["redirect_uris"],
            "client_id": registered["client_id"],
        },
        headers=headers_of(registered),
    )
    assert "scope" not in res.json


def test_replace_with_invalid_metadata(testapp, registered):
    res = testapp.put_json(
        configuration_url(registered),
        {
            **REGISTRATION,
            "client_id": registered["client_id"],
            "grant_types": ["password"],
        },
        headers=headers_of(registered),
        status=400,
    )
    assert res.json["error"] == "invalid_client_metadata"


def test_switch_to_a_public_client(testapp, registered):
    res = testapp.put_json(
        configuration_url(registered),
        {
            **REGISTRATION,
            "client_id": registered["client_id"],
            "token_endpoint_auth_method": "none",
        },
        headers=headers_of(registered),
    )
    assert "client_secret" not in res.json


# Authlib answers 204 through a Flask Response, which adds a Content-Type.
@pytest.mark.filterwarnings("ignore::webtest.lint.WSGIWarning")
def test_delete_the_client_with_its_tokens(app, testapp):
    registered = register(
        testapp,
        {**REGISTRATION, "grant_types": ["client_credentials"], "response_types": []},
    ).json
    client_credentials_token(testapp, registered)
    testapp.delete(
        configuration_url(registered), headers=headers_of(registered), status=204
    )
    with app.app_context():
        assert Client.query.filter_by(client_id=registered["client_id"]).count() == 0
        assert Token.query.filter_by(client_id=registered["client_id"]).count() == 0


def test_disabled_registration_keeps_the_clients(testapp, configure):
    registered = register(
        testapp,
        {**REGISTRATION, "grant_types": ["client_credentials"], "response_types": []},
    ).json
    configure(settings={"registration": "disabled"})
    testapp.get(
        configuration_url(registered), headers=headers_of(registered), status=404
    )
    testapp.delete(
        configuration_url(registered), headers=headers_of(registered), status=404
    )
    client_credentials_token(testapp, registered)


def test_switch_to_a_secret_method(testapp):
    registered = register(
        testapp, {**REGISTRATION, "token_endpoint_auth_method": "none"}
    ).json
    res = testapp.put_json(
        configuration_url(registered),
        {**REGISTRATION, "client_id": registered["client_id"]},
        headers=headers_of(registered),
    )
    assert res.json["client_secret"]


def test_read_refuses_another_scheme(testapp, registered):
    res = testapp.get(
        configuration_url(registered),
        headers={"Authorization": "Basic abc"},
        status=401,
    )
    assert res.json["error"] == "invalid_token"
