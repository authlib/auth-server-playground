"""The keys that sign the ID tokens."""

import time

from joserfc.jwk import ECKey
from joserfc.jwk import KeySet
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
from joserfc.jwk import import_key

from .models import SigningKey
from .models import db

GENERATORS = {
    "RS256": lambda parameters: RSAKey.generate_key(2048, parameters),
    "PS256": lambda parameters: RSAKey.generate_key(2048, parameters),
    "ES256": lambda parameters: ECKey.generate_key("P-256", parameters),
    "Ed25519": lambda parameters: OKPKey.generate_key("Ed25519", parameters),
}


class KeyInUse(ValueError):
    """The key signs the ID tokens of an enabled algorithm."""


def generate_jwk(alg):
    """Return a new private JWK for the algorithm. Its kid is its thumbprint."""
    key = GENERATORS[alg]({"alg": alg, "use": "sig"})
    key.ensure_kid()
    return key.as_dict(private=True)


def active_key(alg):
    return SigningKey.query.filter_by(alg=alg, active=True).first()


def active_kid(alg):
    key = active_key(alg)
    return key.kid if key else None


def add_key(alg):
    """Add a new active key for the algorithm, and retire the previous one."""
    SigningKey.query.filter_by(alg=alg, active=True).update({"active": False})
    jwk = generate_jwk(alg)
    key = SigningKey(
        kid=jwk["kid"], alg=alg, jwk=jwk, created_at=int(time.time()), active=True
    )
    db.session.add(key)
    return key


def ensure_keys(algorithms):
    """Add an active key for each algorithm that has none. The caller commits."""
    for alg in algorithms:
        if active_key(alg) is None:
            add_key(alg)


def rotate_key(alg):
    key = add_key(alg)
    db.session.commit()
    return key


def delete_key(key, enabled_algorithms):
    if key.active and key.alg in enabled_algorithms:
        raise KeyInUse(key.kid)
    db.session.delete(key)
    db.session.commit()


def all_keys():
    return SigningKey.query.order_by(SigningKey.created_at, SigningKey.kid).all()


def private_key_set():
    """Return the active and retired keys.

    The retired keys still verify the id_token_hint of the ID tokens they
    signed.
    """
    return KeySet([import_key(key.jwk) for key in all_keys()])


def public_jwks():
    return {"keys": [import_key(key.jwk).as_dict(private=False) for key in all_keys()]}
