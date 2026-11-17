import time

import pytest
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from auth_server_playground import keys
from auth_server_playground.models import Token
from auth_server_playground.models import db
from auth_server_playground.store import settings_row
from tests.conftest import make_client
from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import basic_auth
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import client_credentials_token
from tests.utils import consent


def authorization_code_token(testapp, client, *, verifier=None, method="S256"):
    """Run the authorization code flow, with PKCE when a verifier is given."""
    challenge = None
    if verifier and method == "S256":
        challenge = create_s256_code_challenge(verifier)
    elif verifier:
        challenge = verifier

    url = authorize_url(
        response_type="code",
        client_id=client["client_id"],
        redirect_uri=REDIRECT_URI,
        scope="profile",
        code_challenge=challenge,
        code_challenge_method=method if verifier else None,
    )
    code = callback_params(consent(testapp, url))["code"]
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
    return testapp.post(
        "/oauth/token",
        {key: value for key, value in data.items() if value is not None},
        headers=basic_auth(client),
    ).json


def refresh(testapp, client, refresh_token, *, status=200):
    return testapp.post(
        "/oauth/token",
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers=basic_auth(client),
        status=status,
    )


def test_change_applies_without_restart(testapp, client, configure):
    client_credentials_token(testapp, client)
    configure(
        metadata={"grant_types_supported": ["authorization_code", "refresh_token"]}
    )
    res = client_credentials_token(testapp, client, status=400)
    assert res.json["error"] == "unsupported_grant_type"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Authlib answers 400 when client_secret_basic is not allowed, even if "
        "the client sent an Authorization header (RFC 6749 §5.2 asks for 401)."
    ),
)
def test_removed_auth_method_is_refused(testapp, client, configure):
    configure(
        metadata={"token_endpoint_auth_methods_supported": ["client_secret_post"]}
    )
    res = client_credentials_token(testapp, client, status="*")
    assert (
        res.status_int,
        res.json["error"],
        res.headers.get("WWW-Authenticate", "").split(" ")[0],
    ) == (401, "invalid_client", "Basic")


def test_removed_auth_method_gives_invalid_client(testapp, client, configure):
    configure(
        metadata={"token_endpoint_auth_methods_supported": ["client_secret_post"]}
    )
    res = client_credentials_token(testapp, client, status="*")
    assert res.json["error"] == "invalid_client"


def test_public_client_cannot_use_client_credentials(testapp, public_client):
    res = testapp.post(
        "/oauth/token",
        {"grant_type": "client_credentials", "client_id": public_client["client_id"]},
        status=401,
    )
    assert res.json["error"] == "invalid_client"


def test_pkce_required_for_all_clients(logged_in, client):
    url = authorize_url(
        response_type="code",
        client_id=client["client_id"],
        redirect_uri=REDIRECT_URI,
    )
    assert callback_params(logged_in.get(url))["error"] == "invalid_request"


def test_pkce_required_for_public_clients_only(logged_in, client, configure):
    configure(settings={"pkce_required": "public"})
    assert authorization_code_token(logged_in, client)["access_token"]


def test_plain_method_refused_when_not_listed(logged_in, client):
    url = authorize_url(
        response_type="code",
        client_id=client["client_id"],
        redirect_uri=REDIRECT_URI,
        code_challenge="a" * 43,
        code_challenge_method="plain",
    )
    assert callback_params(logged_in.get(url))["error"] == "invalid_request"


def test_plain_method_accepted_when_listed(logged_in, client, configure):
    configure(metadata={"code_challenge_methods_supported": ["S256", "plain"]})
    token = authorization_code_token(
        logged_in, client, verifier="a" * 43, method="plain"
    )
    assert token["access_token"]


def test_pkce_disabled(logged_in, client, configure):
    configure(metadata={"code_challenge_methods_supported": []})
    assert authorization_code_token(logged_in, client)["access_token"]


def test_refresh_with_rotation(logged_in, client):
    first = authorization_code_token(logged_in, client, verifier=generate_token(48))
    second = refresh(logged_in, client, first["refresh_token"]).json
    third = refresh(logged_in, client, second["refresh_token"]).json
    assert third["access_token"]
    res = refresh(logged_in, client, first["refresh_token"], status=400)
    assert res.json["error"] == "invalid_grant"


def test_refresh_without_rotation(logged_in, client, configure):
    configure(settings={"refresh_token_rotation": False})
    first = authorization_code_token(logged_in, client, verifier=generate_token(48))
    second = refresh(logged_in, client, first["refresh_token"]).json
    assert "refresh_token" not in second
    assert refresh(logged_in, client, first["refresh_token"]).json["access_token"]
    logged_in.get("/api/resource", headers=bearer(first["access_token"]), status=401)


def test_access_token_lifetime(testapp, client, configure):
    configure(settings={"access_token_lifetime": 120})
    assert client_credentials_token(testapp, client).json["expires_in"] == 120


def test_unknown_scope_is_refused(testapp, client):
    res = client_credentials_token(testapp, client, scope="admin", status=400)
    assert res.json["error"] == "invalid_scope"


def test_revocation_disabled(testapp, client, configure):
    configure(settings={"revocation_enabled": False})
    token = client_credentials_token(testapp, client).json
    testapp.post(
        "/oauth/revoke",
        {"token": token["access_token"]},
        headers=basic_auth(client),
        status=404,
    )
    testapp.get("/api/resource", headers=bearer(token["access_token"]))


def test_revocation_with_client_secret_post(app, testapp):
    post_client = make_client(
        app,
        client_id="post-client",
        client_secret="post-secret",
        metadata={
            "grant_types": ["client_credentials"],
            "response_types": [],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    credentials = {**post_client, "grant_type": "client_credentials"}
    token = testapp.post("/oauth/token", credentials).json
    testapp.post(
        "/oauth/revoke",
        {
            "token": token["access_token"],
            "client_id": post_client["client_id"],
            "client_secret": post_client["client_secret"],
        },
    )
    testapp.get("/api/resource", headers=bearer(token["access_token"]), status=401)


def test_public_client_revokes_with_its_id(app, testapp, public_client):
    with app.app_context():
        db.session.add(
            Token(
                client_id=public_client["client_id"],
                token_type="Bearer",
                access_token="public-access-token",
                scope="profile",
                issued_at=int(time.time()),
                expires_in=3600,
            )
        )
        db.session.commit()

    testapp.get("/api/resource", headers=bearer("public-access-token"))
    testapp.post(
        "/oauth/revoke",
        {"token": "public-access-token", "client_id": public_client["client_id"]},
    )
    testapp.get("/api/resource", headers=bearer("public-access-token"), status=401)


def test_revocation_needs_the_secret(testapp, client):
    token = client_credentials_token(testapp, client).json
    res = testapp.post(
        "/oauth/revoke",
        {"token": token["access_token"], "client_id": client["client_id"]},
        status="4*",
    )
    assert res.json["error"] == "invalid_client"
    testapp.get("/api/resource", headers=bearer(token["access_token"]))


def test_metadata(testapp):
    metadata = testapp.get("/.well-known/oauth-authorization-server").json
    assert metadata["issuer"] == "http://localhost"
    assert metadata["authorization_endpoint"] == "http://localhost/oauth/authorize"
    assert metadata["token_endpoint"] == "http://localhost/oauth/token"
    assert metadata["revocation_endpoint"] == "http://localhost/oauth/revoke"
    assert metadata["grant_types_supported"] == [
        "authorization_code",
        "refresh_token",
        "client_credentials",
    ]


def test_metadata_with_issuer(testapp, configure):
    configure(metadata={"issuer": "https://issuer.test"})
    metadata = testapp.get("/.well-known/oauth-authorization-server").json
    assert metadata["issuer"] == "https://issuer.test"


def test_resource_returns_the_persona(logged_in, client, persona, configure):
    configure(settings={"pkce_required": "public"})
    token = authorization_code_token(logged_in, client)
    res = logged_in.get("/api/resource", headers=bearer(token["access_token"]))
    assert res.json == {
        "sub": persona["sub"],
        "scope": "profile",
        "client_id": client["client_id"],
    }


def test_resource_without_persona(testapp, client):
    token = client_credentials_token(testapp, client, scope="profile").json
    res = testapp.get("/api/resource", headers=bearer(token["access_token"]))
    assert res.json == {"scope": "profile", "client_id": client["client_id"]}


def test_revision_goes_up_on_each_save(app, configure):
    with app.app_context():
        before = settings_row().revision

    configure(settings={"access_token_lifetime": 60})
    configure(settings={"access_token_lifetime": 120})
    with app.app_context():
        assert settings_row().revision == before + 2


def test_refresh_token_lifetime(app, logged_in, client, configure):
    configure(settings={"refresh_token_lifetime": 600})
    token = authorization_code_token(logged_in, client, verifier=generate_token(48))
    with app.app_context():
        row = Token.query.filter_by(refresh_token=token["refresh_token"]).one()
        assert row.refresh_token_expires_at == row.issued_at + 600
        row.refresh_token_expires_at = int(time.time()) - 1
        db.session.commit()

    res = refresh(logged_in, client, token["refresh_token"], status=400)
    assert res.json["error"] == "invalid_grant"


def test_refresh_token_lifetime_does_not_follow_the_access_token(
    app, logged_in, client, configure
):
    configure(settings={"access_token_lifetime": 1, "refresh_token_lifetime": 600})
    token = authorization_code_token(logged_in, client, verifier=generate_token(48))
    with app.app_context():
        row = Token.query.filter_by(refresh_token=token["refresh_token"]).one()
        row.issued_at -= 10
        db.session.commit()

    assert refresh(logged_in, client, token["refresh_token"]).json["access_token"]


def test_openid_configuration(testapp):
    res = testapp.get("/.well-known/openid-configuration")
    assert res.json["issuer"] == "http://localhost"
    assert res.json["jwks_uri"] == "http://localhost/oauth/jwks"
    assert res.json == testapp.get("/.well-known/oauth-authorization-server").json


def test_openid_configuration_without_openid(testapp, configure):
    configure(metadata={"scopes_supported": ["profile"]})
    testapp.get("/.well-known/openid-configuration", status=404)


def test_new_database_has_a_key(app):
    with app.app_context():
        assert keys.active_kid("RS256") is not None


def test_saving_a_new_algorithm_creates_its_key(app, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "ES256"]})
    with app.app_context():
        assert keys.active_kid("ES256") is not None


def test_disabling_an_algorithm_keeps_its_key(app, configure):
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256", "ES256"]})
    configure(metadata={"id_token_signing_alg_values_supported": ["RS256"]})
    with app.app_context():
        assert keys.active_kid("ES256") is not None
