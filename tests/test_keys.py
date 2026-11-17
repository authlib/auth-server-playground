import copy
import datetime
import functools
import warnings

import pytest
from joserfc.jwk import ECKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
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


def test_the_algorithm_tables_agree():
    assert set(keys.GENERATORS) == set(keys.KEY_TYPES) == set(ID_TOKEN_ALGORITHMS)


@functools.cache
def rsa_jwk(alg):
    key = RSAKey.generate_key(2048, {"alg": alg, "use": "sig"})
    key.ensure_kid()
    return key.as_dict(private=True)


def valid_jwk(alg):
    """Return a new JWK that is_valid_key accepts. The RSA keys are shared."""
    if alg in ("RS256", "PS256"):
        return copy.deepcopy(rsa_jwk(alg))

    jwk = REAL_GENERATORS[alg]({"alg": alg, "use": "sig"})
    jwk.ensure_kid()
    return jwk.as_dict(private=True)


@pytest.mark.parametrize("alg", ID_TOKEN_ALGORITHMS)
def test_generated_jwk_is_valid(alg):
    jwk = valid_jwk(alg)
    assert keys.is_valid_key(jwk, alg, jwk["kid"])


def test_jwk_without_use_and_key_ops_is_valid():
    jwk = valid_jwk("ES256")
    del jwk["use"]
    assert keys.is_valid_key(jwk, "ES256", jwk["kid"])


def mixed_okp(kid_of):
    """Return an Ed25519 JWK with the d of a key and the x of another.

    kid_of tells which key gives the kid: the one of "d" or the one of "x".
    """
    jwk = valid_jwk("Ed25519")
    other = valid_jwk("Ed25519")
    if kid_of == "x":
        jwk["kid"] = other["kid"]

    jwk["x"] = other["x"]
    return jwk


def small_rsa():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = RSAKey.generate_key(1024, {"alg": "RS256", "use": "sig"})

    key.ensure_kid()
    return key.as_dict(private=True)


def other_curve(key_class, curve, alg):
    key = key_class.generate_key(curve, {"alg": alg, "use": "sig"})
    key.ensure_kid()
    return key.as_dict(private=True)


def jwk_with(base, **changes):
    jwk = valid_jwk(base)
    jwk.update(changes)
    return jwk


@pytest.mark.parametrize(
    ("alg", "jwk"),
    [
        ("ES256", other_curve(ECKey, "P-384", "ES256")),
        ("Ed25519", other_curve(OKPKey, "X25519", "Ed25519")),
        ("RS256", jwk_with("ES256")),
        ("RS256", jwk_with("RS256", alg="PS256")),
        ("RS256", jwk_with("RS256", kid="other")),
        ("Ed25519", mixed_okp("x")),
        ("Ed25519", mixed_okp("d")),
        ("RS256", jwk_with("RS256", use="enc")),
        ("RS256", jwk_with("RS256", key_ops=["verify"])),
        ("RS256", small_rsa()),
        ("RS256", jwk_with("RS256", n=None)),
        ("RS256", jwk_with("RS256", n="!")),
        ("RS256", jwk_with("RS256", e="!")),
        ("ES256", jwk_with("ES256", crv=["P-256"])),
        ("Ed25519", jwk_with("Ed25519", crv="Foo")),
        ("RS256", jwk_with("RS256", kty=["RSA"])),
        ("RS256", {"kty": "RSA"}),
        ("RS256", "text"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_invalid_jwk(alg, jwk):
    kid = jwk["kid"] if isinstance(jwk, dict) and "kid" in jwk else "kid"
    assert not keys.is_valid_key(jwk, alg, kid)


def test_jwk_kid_must_be_the_item_kid():
    jwk = valid_jwk("RS256")
    assert not keys.is_valid_key(jwk, "RS256", "other")


def test_public_jwk_is_not_valid():
    jwk = valid_jwk("ES256")
    del jwk["d"]
    assert not keys.is_valid_key(jwk, "ES256", jwk["kid"])
