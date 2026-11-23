import json

import pytest
from webtest import Upload

from auth_server_playground import keys
from auth_server_playground.models import SETTINGS_ID
from auth_server_playground.models import Client
from auth_server_playground.models import Consent
from auth_server_playground.models import Persona
from auth_server_playground.models import Settings
from auth_server_playground.models import Token
from auth_server_playground.models import db
from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.settings import MAX_LIFETIME
from auth_server_playground.snapshot import MAX_TIMESTAMP
from auth_server_playground.snapshot import SnapshotError
from auth_server_playground.snapshot import check_snapshot
from auth_server_playground.snapshot import export_snapshot
from auth_server_playground.snapshot import import_snapshot
from auth_server_playground.store import save_document
from tests.test_authorization_code import code_url
from tests.utils import client_credentials_token
from tests.utils import consent


def test_round_trip(app, client, configure):
    configure(settings={"access_token_lifetime": 60})
    with app.app_context():
        snapshot = export_snapshot()
        Persona.query.delete()
        db.session.commit()
        import_snapshot(snapshot)
        assert export_snapshot() == snapshot


def test_snapshot_content(app, client):
    with app.app_context():
        snapshot = export_snapshot()
        secret_key = db.session.get(Settings, SETTINGS_ID).secret_key

    assert snapshot["version"] == 1
    assert snapshot["configuration"]["settings"]["access_token_lifetime"] == 3600
    assert COMPLETE_SUB in {persona["sub"] for persona in snapshot["personas"]}
    assert snapshot["clients"][0]["client_secret"] == client["client_secret"]
    assert secret_key not in json.dumps(snapshot)


def test_import_purges_tokens_and_keeps_the_secret_key(app, testapp, client):
    client_credentials_token(testapp, client)
    with app.app_context():
        key = db.session.get(Settings, SETTINGS_ID).secret_key
        import_snapshot(export_snapshot())
        assert Token.query.count() == 0
        assert db.session.get(Settings, SETTINGS_ID).secret_key == key


def test_import_deletes_the_consents(app, logged_in, client):
    consent(logged_in, code_url(client))
    with app.app_context():
        assert Consent.query.count() == 1
        import_snapshot(export_snapshot())
        assert Consent.query.count() == 0


def test_import_bumps_the_revision(app):
    with app.app_context():
        before = db.session.get(Settings, SETTINGS_ID).revision
        import_snapshot(export_snapshot())
        assert db.session.get(Settings, SETTINGS_ID).revision == before + 1


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.clear(),
        lambda s: s.update(version=2),
        lambda s: s.pop("clients"),
        lambda s: s.update(personas={}),
        lambda s: s["configuration"]["settings"].update(pkce_required="never"),
        lambda s: s["personas"].append(dict(s["personas"][0])),
        lambda s: s["personas"].append("alice"),
        lambda s: s["personas"][0].update(sub="x" * 256),
        lambda s: s["personas"][0].update(claims="not an object"),
        lambda s: s["personas"][0].update(picture_svg=42),
        lambda s: s["personas"][0]["claims"].update(preferred_username=["a"]),
        lambda s: s["personas"][0]["claims"].update(address="Paris"),
        lambda s: s["personas"][0]["claims"].update(email_verified="yes"),
        lambda s: s["personas"][0]["claims"].update(updated_at=True),
        lambda s: s["configuration"]["metadata"].update(
            grant_types_supported=[["authorization_code"]]
        ),
        lambda s: s["personas"][1]["claims"].update(
            preferred_username=s["personas"][0]["claims"]["preferred_username"]
        ),
        lambda s: s["clients"].append(dict(s["clients"][0])),
        lambda s: s["clients"].append(None),
        lambda s: s["clients"][0].update(client_id="a/b"),
        lambda s: s["clients"][0].update(client_secret=42),
        lambda s: s["clients"][0].update(client_id_issued_at="now"),
        lambda s: s["clients"][0].update(client_id_issued_at=True),
        lambda s: s["clients"][0].update(client_id_issued_at=2**70),
        lambda s: s["clients"][0].update(client_secret_expires_at=-1),
        lambda s: s["clients"][0].update(client_metadata=[]),
        lambda s: s["clients"][0]["client_metadata"].update(scope=["profile"]),
        lambda s: s["clients"][0]["client_metadata"].update(
            redirect_uris="https://good.example/cb"
        ),
    ],
)
def test_invalid_import_changes_nothing(app, client, change):
    with app.app_context():
        snapshot = export_snapshot()
        before = json.dumps(snapshot, sort_keys=True)
        change(snapshot)
        with pytest.raises(SnapshotError):
            import_snapshot(snapshot)

        assert json.dumps(export_snapshot(), sort_keys=True) == before


def test_not_an_object(app):
    with app.app_context(), pytest.raises(SnapshotError):
        import_snapshot([])


def test_database_error_rolls_back(app, client, monkeypatch):
    with app.app_context():
        snapshot = export_snapshot()
        before = json.dumps(snapshot, sort_keys=True)
        snapshot["clients"] = []

        def fail():
            raise RuntimeError("database error")

        monkeypatch.setattr(db.session, "commit", fail)
        with pytest.raises(RuntimeError):
            import_snapshot(snapshot)

        monkeypatch.undo()
        assert json.dumps(export_snapshot(), sort_keys=True) == before


def test_import_from_the_interface(app, testapp, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"] = []
    form = testapp.get("/en/snapshot").forms["import"]
    form["file"] = Upload(
        "snapshot.json", json.dumps(snapshot).encode(), "application/json"
    )
    res = form.submit()
    assert "0 clients" in res.text
    res = res.forms["confirm"].submit().follow()
    assert 'role="status"' in res.text
    with app.app_context():
        assert export_snapshot()["clients"] == []


def test_persona_ids_are_not_reused(app, persona):
    with app.app_context():
        snapshot = export_snapshot()
        import_snapshot(snapshot)
        ids = {row.id for row in Persona.query}

    assert persona["id"] not in ids


def test_import_forgets_the_persona(app, logged_in):
    with app.app_context():
        snapshot = export_snapshot()

    form = logged_in.get("/en/snapshot").forms["import"]
    form["file"] = Upload(
        "snapshot.json", json.dumps(snapshot).encode(), "application/json"
    )
    form.submit().forms["confirm"].submit()
    assert "Forget persona" not in logged_in.get("/en/")


def test_import_a_large_snapshot(app, testapp):
    with app.app_context():
        snapshot = export_snapshot()

    template = snapshot["personas"][0]
    snapshot["personas"] = [
        {
            "sub": f"persona-{index}",
            "claims": {"preferred_username": f"persona{index}"},
            "picture_svg": "<svg>" + " " * 30_000 + "</svg>",
        }
        for index in range(20)
    ]
    snapshot["personas"].append(template)
    assert len(json.dumps(snapshot)) > 500_000
    form = testapp.get("/en/snapshot").forms["import"]
    form["file"] = Upload(
        "snapshot.json", json.dumps(snapshot).encode(), "application/json"
    )
    form.submit().forms["confirm"].submit()
    with app.app_context():
        assert Persona.query.count() == 21


@pytest.mark.parametrize(
    "content",
    [
        b"{not json",
        b"\xff\xfe",
        b'{"version": 2}',
        b"[]",
        b"1" * 5000,
        b"[" * 100_000 + b"]" * 100_000,
    ],
)
def test_unreadable_file(testapp, content):
    form = testapp.get("/en/snapshot").forms["import"]
    form["file"] = Upload("snapshot.json", content, "application/json")
    res = form.submit()
    assert res.status_int == 200
    assert 'role="alert"' in res.text
    assert "confirm" not in res.forms


def test_import_needs_a_file(testapp):
    res = testapp.get("/en/snapshot").forms["import"].submit()
    assert res.status_int == 200
    assert "confirm" not in res.forms


def test_confirm_an_invalid_snapshot(app, testapp, client):
    with app.app_context():
        snapshot = export_snapshot()

    form = testapp.get("/en/snapshot").forms["import"]
    form["file"] = Upload(
        "snapshot.json", json.dumps(snapshot).encode(), "application/json"
    )
    confirm = form.submit().forms["confirm"]
    confirm["snapshot"] = "{not json"
    res = confirm.submit().follow()
    assert 'role="alert"' in res.text
    with app.app_context():
        assert export_snapshot() == snapshot


def test_confirm_needs_a_csrf_token(app, testapp, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"] = []
    testapp.post("/en/snapshot/confirm", {"snapshot": json.dumps(snapshot)})
    with app.app_context():
        assert export_snapshot()["clients"] != []


def test_export_download(testapp):
    res = testapp.get("/en/snapshot/export")
    assert res.content_type == "application/json"
    assert "attachment" in res.headers["Content-Disposition"]
    assert res.json["version"] == 1


def write_snapshot(app, tmp_path, lifetime):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["configuration"]["settings"]["access_token_lifetime"] = lifetime
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot))
    return path


def lifetime(app):
    with app.app_context():
        return export_snapshot()["configuration"]["settings"]["access_token_lifetime"]


def test_initial_snapshot_on_empty_database(app, tmp_path, make_app, monkeypatch):
    with app.app_context():
        keys.rotate_key("RS256")

    path = write_snapshot(app, tmp_path, 42)
    snapshot_keys = json.loads(path.read_text())["keys"]
    monkeypatch.setenv("INITIAL_SNAPSHOT", str(path))
    database = f"sqlite:///{tmp_path}/db.sqlite"

    first = make_app(database)
    assert lifetime(first) == 42
    assert len(snapshot_keys) == 2
    with first.app_context():
        assert export_snapshot()["keys"] == snapshot_keys
        document = export_snapshot()["configuration"]
        document["settings"]["access_token_lifetime"] = 7
        save_document(document)

    assert lifetime(make_app(database)) == 7


def test_invalid_initial_snapshot(tmp_path, make_app, monkeypatch):
    path = tmp_path / "snapshot.json"
    path.write_text('{"version": 2}')
    monkeypatch.setenv("INITIAL_SNAPSHOT", str(path))
    with pytest.raises(SnapshotError):
        make_app()


@pytest.mark.parametrize(
    "key",
    [
        "userinfo_encrypted_response_alg",
        "userinfo_encrypted_response_enc",
        "id_token_encrypted_response_alg",
        "id_token_encrypted_response_enc",
    ],
)
def test_unsupported_client_metadata_is_refused(app, client, key):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"][key] = "RS256"
    with pytest.raises(SnapshotError, match=key):
        check_snapshot(snapshot)


@pytest.mark.parametrize(
    "value",
    ["soon", True, -1, 1.5, float("nan"), float("inf"), 10**30, MAX_LIFETIME + 1],
)
def test_invalid_default_max_age_is_refused(app, client, value):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["default_max_age"] = value
    with pytest.raises(SnapshotError, match="default_max_age"):
        check_snapshot(snapshot)


@pytest.mark.parametrize("value", [0, 30, MAX_LIFETIME])
def test_valid_default_max_age_is_accepted(app, client, value):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["default_max_age"] = value
    check_snapshot(snapshot)


@pytest.mark.parametrize("alg", ["none", "HS256", "foo", "EdDSA", "RS384"])
def test_unsignable_client_algorithm_is_refused(app, client, alg):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["id_token_signed_response_alg"] = alg
    with pytest.raises(SnapshotError, match="id_token_signed_response_alg"):
        check_snapshot(snapshot)


def test_signed_userinfo_algorithm_is_accepted(app, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["userinfo_signed_response_alg"] = "RS256"
    check_snapshot(snapshot)


def test_unsignable_userinfo_algorithm_is_refused(app, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["userinfo_signed_response_alg"] = "HS256"
    with pytest.raises(SnapshotError, match="userinfo_signed_response_alg"):
        check_snapshot(snapshot)


def test_null_unsupported_client_metadata_is_accepted(app, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["userinfo_encrypted_response_alg"] = None
    check_snapshot(snapshot)


def test_client_algorithm_unknown_to_the_server_is_accepted(app, client):
    with app.app_context():
        snapshot = export_snapshot()

    snapshot["clients"][0]["client_metadata"]["id_token_signed_response_alg"] = "ES256"
    check_snapshot(snapshot)


def test_imported_client_has_no_default_algorithm(app, client):
    with app.app_context():
        snapshot = export_snapshot()
        import_snapshot(snapshot)
        stored = Client.query.filter_by(client_id="confidential-client").one()
        assert "id_token_signed_response_alg" not in stored.client_metadata


def test_export_has_the_keys(app):
    with app.app_context():
        snapshot = export_snapshot()
        assert [key["kid"] for key in snapshot["keys"]] == [
            key.kid for key in keys.all_keys()
        ]
        assert "d" in snapshot["keys"][0]["jwk"]


def test_export_then_import_keeps_the_keys(app):
    with app.app_context():
        keys.rotate_key("RS256")
        snapshot = export_snapshot()
        import_snapshot(snapshot)
        assert export_snapshot()["keys"] == snapshot["keys"]


def test_missing_key_is_generated(app):
    with app.app_context():
        snapshot = export_snapshot()
        snapshot["keys"] = []
        import_snapshot(snapshot)
        assert keys.active_kid("RS256") is not None


def with_key(snapshot, **changes):
    snapshot["keys"][0].update(changes)
    return snapshot


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda s: s.pop("keys"), "no 'keys'"),
        (lambda s: s.update(keys="none"), "list of JSON objects"),
        (lambda s: s.update(keys=["none"]), "list of JSON objects"),
        (lambda s: with_key(s, alg="EdDSA"), "Unknown key algorithm"),
        (lambda s: with_key(s, alg=["RS256"]), "Unknown key algorithm"),
        (lambda s: with_key(s, alg="ES256"), "private ES256 key"),
        (lambda s: with_key(s, kid="other"), "private RS256 key"),
        (lambda s: with_key(s, jwk="text"), "private RS256 key"),
        (lambda s: with_key(s, jwk={"kty": "unknown"}), "private RS256 key"),
        (lambda s: with_key(s, jwk={"kty": ["RSA"]}), "private RS256 key"),
        (lambda s: with_key(s, jwk={"kty": "RSA"}), "private RS256 key"),
        (lambda s: s["keys"][0]["jwk"].update(use="enc"), "private RS256 key"),
        (lambda s: s["keys"][0]["jwk"].update(key_ops=["verify"]), "private RS256 key"),
        (lambda s: s["keys"][0]["jwk"].pop("d"), "private RS256 key"),
        (lambda s: with_key(s, created_at="today"), "created_at"),
        (lambda s: with_key(s, created_at=True), "created_at"),
        (lambda s: with_key(s, created_at=None), "created_at"),
        (lambda s: with_key(s, created_at=-1), "created_at"),
        (lambda s: with_key(s, created_at=10**12), "created_at"),
        (lambda s: with_key(s, created_at=2**70), "created_at"),
        (lambda s: with_key(s, active="yes"), "true or false"),
        (lambda s: s["keys"].append(dict(s["keys"][0])), "own kid"),
    ],
)
def test_invalid_keys_are_refused(app, change, message):
    with app.app_context():
        snapshot = export_snapshot()

    change(snapshot)
    with pytest.raises(SnapshotError, match=message):
        check_snapshot(snapshot)


def test_key_with_the_maximum_created_at_is_accepted(app):
    with app.app_context():
        snapshot = export_snapshot()

    with_key(snapshot, created_at=MAX_TIMESTAMP)
    check_snapshot(snapshot)


def test_two_active_keys_for_one_algorithm_are_refused(app):
    with app.app_context():
        keys.rotate_key("RS256")
        snapshot = export_snapshot()

    for key in snapshot["keys"]:
        key["active"] = True

    with pytest.raises(SnapshotError, match="active"):
        check_snapshot(snapshot)


def test_confirm_page_counts_the_keys(app, testapp):
    with app.app_context():
        snapshot = export_snapshot()

    form = testapp.get("/en/snapshot").forms["import"]
    form["file"] = Upload(
        "snapshot.json", json.dumps(snapshot).encode(), "application/json"
    )
    assert "1 key." in form.submit().text


def test_dynamic_client_survives_export_and_import(app, dynamic_client):
    with app.app_context():
        data = export_snapshot()
        import_snapshot(data)
        client = Client.query.filter_by(client_id="dynamic-client").one()
        assert client.registration_access_token == "dynamic-registration-token"


@pytest.mark.parametrize(
    "client_values,message",
    [
        ({"registration_access_token": 42}, "string of 1 to 255"),
        ({"registration_access_token": ""}, "string of 1 to 255"),
        (
            {"client_metadata": {"token_endpoint_auth_method": "private_key_jwt"}},
            "private_key_jwt needs jwks or jwks_uri",
        ),
        (
            {"client_metadata": {"token_endpoint_auth_method": ["private_key_jwt"]}},
            "token_endpoint_auth_method",
        ),
        (
            {"client_metadata": {"token_endpoint_auth_signing_alg": "HS512"}},
            "token_endpoint_auth_signing_alg",
        ),
        (
            {"client_metadata": {"request_object_signing_alg": "EdDSA"}},
            "request_object_signing_alg",
        ),
        (
            {"client_metadata": {"require_signed_request_object": "yes"}},
            "require_signed_request_object",
        ),
        (
            {
                "client_metadata": {
                    "jwks": {
                        "keys": [
                            {"kty": "oct", "k": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"}
                        ]
                    }
                }
            },
            "jwks",
        ),
    ],
)
def test_invalid_client_key_values(app, client_values, message):
    with app.app_context():
        data = export_snapshot()

    data["clients"] = [
        {"client_id": "c", "client_metadata": {}, **client_values},
    ]
    with pytest.raises(SnapshotError, match=message):
        check_snapshot(data)


def test_registration_access_tokens_are_unique(app):
    with app.app_context():
        data = export_snapshot()

    data["clients"] = [
        {"client_id": "a", "client_metadata": {}, "registration_access_token": "t"},
        {"client_id": "b", "client_metadata": {}, "registration_access_token": "t"},
    ]
    with pytest.raises(SnapshotError, match="registration_access_token"):
        check_snapshot(data)
