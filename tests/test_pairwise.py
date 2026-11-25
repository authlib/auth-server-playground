import base64
import hashlib

from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.store import current_document
from tests.conftest import make_client
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import decode_id_token
from tests.utils import exchange_code
from tests.utils import oidc_url


def pairwise_client(app, client_id, **metadata):
    return make_client(
        app,
        client_id=client_id,
        client_secret=f"{client_id}-secret",
        metadata={
            "scope": "openid profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "subject_type": "pairwise",
            **metadata,
        },
    )


def subjects(testapp, client):
    """Return the sub of the ID token, of UserInfo and of /api/resource."""
    code = callback_params(consent(testapp, oidc_url(client)))["code"]
    body = exchange_code(testapp, client, code).json
    headers = bearer(body["access_token"])
    return (
        decode_id_token(testapp, body["id_token"]).claims["sub"],
        testapp.get("/oauth/userinfo", headers=headers).json["sub"],
        testapp.get("/api/resource", headers=headers).json["sub"],
    )


def expected_sub(app, sector):
    with app.app_context():
        salt = current_document()["settings"]["pairwise_salt"]

    digest = hashlib.sha256(f"{sector}{COMPLETE_SUB}{salt}".encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_pairwise_sub_is_the_same_everywhere(app, logged_in, pairwise_server):
    client = pairwise_client(app, "pairwise-client")
    assert subjects(logged_in, client) == (expected_sub(app, "client.test"),) * 3


def test_sector_identifier_uri_gives_the_sector(app, logged_in, pairwise_server):
    client = pairwise_client(
        app, "pairwise-client", sector_identifier_uri="https://sector.test/uris.json"
    )
    assert subjects(logged_in, client)[0] == expected_sub(app, "sector.test")


def test_clients_of_one_sector_share_the_sub(app, logged_in, pairwise_server):
    first = pairwise_client(app, "first-client")
    second = pairwise_client(app, "second-client")
    assert subjects(logged_in, first) == subjects(logged_in, second)


def test_two_sectors_give_two_subs(app, logged_in, pairwise_server):
    first = pairwise_client(
        app, "first-client", sector_identifier_uri="https://first.test/uris.json"
    )
    second = pairwise_client(
        app, "second-client", sector_identifier_uri="https://second.test/uris.json"
    )
    assert subjects(logged_in, first) != subjects(logged_in, second)


def test_public_client_gets_the_persona_sub(logged_in, client):
    assert subjects(logged_in, client) == (COMPLETE_SUB,) * 3


def test_pairwise_only_server_gives_pairwise_subs_by_default(app, logged_in, configure):
    configure(metadata={"subject_types_supported": ["pairwise"]})
    client = pairwise_client(app, "default-client", subject_type=None)
    assert subjects(logged_in, client) == (expected_sub(app, "client.test"),) * 3


def test_public_and_pairwise_server_gives_public_subs_by_default(
    app, logged_in, pairwise_server
):
    client = pairwise_client(app, "default-client", subject_type=None)
    assert subjects(logged_in, client) == (COMPLETE_SUB,) * 3


def test_id_token_hint_of_a_pairwise_client(app, logged_in, pairwise_server):
    client = pairwise_client(app, "pairwise-client")
    code = callback_params(consent(logged_in, oidc_url(client)))["code"]
    id_token = exchange_code(logged_in, client, code).json["id_token"]
    res = logged_in.get(oidc_url(client, prompt="none", id_token_hint=id_token))
    assert "code" in callback_params(res)
