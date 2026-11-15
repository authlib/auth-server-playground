import datetime

import pytest
from joserfc.jwk import import_key

from auth_server_playground import keys
from auth_server_playground.keys import KeyInUse
from auth_server_playground.models import SigningKey
from auth_server_playground.models import db
from auth_server_playground.settings import ID_TOKEN_ALGORITHMS
from tests.conftest import REAL_GENERATORS

KEY_TYPES = {
    "RS256": ("RSA", None),
    "PS256": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "Ed25519": ("OKP", "Ed25519"),
}


@pytest.mark.parametrize("alg", ID_TOKEN_ALGORITHMS)
def test_generated_key(monkeypatch, alg):
    monkeypatch.setitem(keys.GENERATORS, alg, REAL_GENERATORS[alg])
    jwk = keys.generate_jwk(alg)
    key = import_key(jwk)
    assert key.is_private
    assert (key.key_type, key.get("crv")) == KEY_TYPES[alg]
    assert jwk["alg"] == alg
    assert jwk["use"] == "sig"
    assert jwk["kid"] == key.thumbprint()


def test_rsa_keys_have_2048_bits(monkeypatch):
    monkeypatch.setitem(keys.GENERATORS, "RS256", REAL_GENERATORS["RS256"])
    key = import_key(keys.generate_jwk("RS256"))
    assert key.private_key.key_size == 2048


def test_ensure_keys_adds_one_active_key_per_algorithm(app):
    with app.app_context():
        keys.ensure_keys(["RS256", "ES256"])
        keys.ensure_keys(["RS256", "ES256"])
        db.session.commit()
        active = SigningKey.query.filter_by(active=True).all()
        assert sorted(key.alg for key in active) == ["ES256", "RS256"]


def test_rotation_retires_the_previous_key(app):
    with app.app_context():
        old = keys.active_kid("RS256")
        new = keys.rotate_key("RS256").kid
        assert keys.active_kid("RS256") == new != old
        assert db.session.get(SigningKey, old).active is False


def test_retired_key_can_be_deleted(app):
    with app.app_context():
        old = keys.active_kid("RS256")
        keys.rotate_key("RS256")
        keys.delete_key(db.session.get(SigningKey, old), ["RS256"])
        assert db.session.get(SigningKey, old) is None


def test_active_key_of_an_enabled_algorithm_cannot_be_deleted(app):
    with app.app_context():
        key = db.session.get(SigningKey, keys.active_kid("RS256"))
        with pytest.raises(KeyInUse):
            keys.delete_key(key, ["RS256"])


def test_active_key_of_a_disabled_algorithm_can_be_deleted(app):
    with app.app_context():
        keys.ensure_keys(["ES256"])
        db.session.commit()
        key = db.session.get(SigningKey, keys.active_kid("ES256"))
        keys.delete_key(key, ["RS256"])
        assert keys.active_kid("ES256") is None


def test_private_key_set_holds_retired_keys(app):
    with app.app_context():
        old = keys.active_kid("RS256")
        new = keys.rotate_key("RS256").kid
        kids = {key.kid for key in keys.private_key_set().keys}
        assert {old, new} <= kids


def test_created_is_an_aware_datetime(app):
    with app.app_context():
        key = db.session.get(SigningKey, keys.active_kid("RS256"))
        assert key.created.tzinfo is not None
        assert key.created == datetime.datetime.fromtimestamp(
            key.created_at, datetime.UTC
        )


def test_jwks_publishes_the_public_keys(app, testapp):
    with app.app_context():
        keys.rotate_key("RS256")
        kids = [key.kid for key in keys.all_keys()]

    res = testapp.get("/oauth/jwks")
    assert res.headers["Cache-Control"] == "no-cache"
    assert [jwk["kid"] for jwk in res.json["keys"]] == kids
    for jwk in res.json["keys"]:
        assert "d" not in jwk
        assert jwk["alg"] == "RS256"


def test_empty_jwks(app, testapp):
    with app.app_context():
        SigningKey.query.delete()
        db.session.commit()
    assert testapp.get("/oauth/jwks").json == {"keys": []}
