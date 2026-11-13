from auth_server_playground.models import Client
from auth_server_playground.models import db
from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import password_token


def test_api_me_needs_a_token(testapp):
    res = testapp.get("/api/me", status=401)
    assert res.headers["WWW-Authenticate"] == "Bearer"


def test_api_me_rejects_an_unknown_token(testapp):
    res = testapp.get("/api/me", headers=bearer("unknown"), status=401)
    assert res.json["error"] == "invalid_token"


def test_api_me_needs_the_profile_scope(app, testapp, client, persona):
    with app.app_context():
        db_client = Client.query.filter_by(client_id=client["client_id"]).one()
        db_client.set_client_metadata({**db_client.client_metadata, "scope": "email"})
        db.session.commit()

    token = password_token(testapp, client, persona, scope="email").json
    res = testapp.get("/api/me", headers=bearer(token["access_token"]), status=403)
    assert res.json["error"] == "insufficient_scope"


def test_revocation(testapp, client, persona):
    token = password_token(testapp, client, persona).json
    testapp.get("/api/me", headers=bearer(token["access_token"]))

    testapp.post(
        "/oauth/revoke",
        {"token": token["access_token"], "token_type_hint": "access_token"},
        headers=basic_auth(client),
    )

    testapp.get("/api/me", headers=bearer(token["access_token"]), status=401)


def test_api_me_without_persona(testapp, client):
    token = testapp.post(
        "/oauth/token",
        {"grant_type": "client_credentials", "scope": "profile"},
        headers=basic_auth(client),
    ).json
    res = testapp.get("/api/me", headers=bearer(token["access_token"]))
    assert res.json == {}


def test_api_me_leaves_out_missing_claims(testapp, client, other_persona):
    persona = {**other_persona, "preferred_username": "bob"}
    token = password_token(testapp, client, persona).json
    res = testapp.get("/api/me", headers=bearer(token["access_token"]))
    assert res.json == {"sub": other_persona["sub"], "preferred_username": "bob"}
