"""The keys that sign the ID tokens and the UserInfo responses."""

import time

from joserfc.errors import JoseError
from joserfc.jwk import ECKey
from joserfc.jwk import KeySet
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey
from joserfc.jwk import import_key
from joserfc.util import base64_to_int

from .models import SigningKey
from .models import db

GENERATORS = {
    "RS256": lambda parameters: RSAKey.generate_key(2048, parameters),
    "PS256": lambda parameters: RSAKey.generate_key(2048, parameters),
    "ES256": lambda parameters: ECKey.generate_key("P-256", parameters),
    "Ed25519": lambda parameters: OKPKey.generate_key("Ed25519", parameters),
}

#: The key type and curve of each algorithm.
KEY_TYPES = {
    "RS256": ("RSA", None),
    "PS256": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "Ed25519": ("OKP", "Ed25519"),
}


#: Per RFC 7518 §3.3 and §3.5, RS256 and PS256 need a key of 2048 bits or more.
MIN_RSA_BITS = 2048


class KeyInUse(ValueError):
    """The key is the active key of an enabled algorithm."""


def generate_jwk(alg):
    """Return a new private JWK for the algorithm. Its kid is its thumbprint."""
    key = GENERATORS[alg]({"alg": alg, "use": "sig"})
    key.ensure_kid()
    return key.as_dict(private=True)


def is_long_rsa_modulus(n):
    return isinstance(n, str) and base64_to_int(n).bit_length() >= MIN_RSA_BITS


def is_valid_key(jwk, alg, kid):
    """Tell if the JWK is a private signing key of the algorithm, with its thumbprint as kid."""
    if not isinstance(jwk, dict) or (jwk.get("kty"), jwk.get("crv")) != KEY_TYPES[alg]:
        return False

    try:
        # joserfc only warns about a short RSA key, and signs with it.
        if jwk["kty"] == "RSA" and not is_long_rsa_modulus(jwk.get("n")):
            return False

        # joserfc raises ValueError, KeyError or TypeError, not only JoseError,
        # for some malformed keys. The pre-check above covers kty and crv.
        key = import_key(jwk)
        key.check_use("sig")
        key.check_key_op("sign")
        # joserfc builds a private OKP key from "d" and ignores "x". So the
        # public part of the JWK must give the same thumbprint as "d".
        public = import_key(key.as_pem(private=False), key.key_type)
    except (JoseError, ValueError):
        return False

    return (
        key.is_private
        and key.alg == alg
        and key.kid == kid == key.thumbprint() == public.thumbprint()
    )


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


def active_key_set():
    """Return the active keys, one per algorithm."""
    return KeySet(
        [import_key(key.jwk) for key in SigningKey.query.filter_by(active=True)]
    )


def private_key_set():
    """Return the active and retired keys.

    The retired keys still verify the id_token_hint of the ID tokens they
    signed.
    """
    return KeySet([import_key(key.jwk) for key in all_keys()])


def public_jwks():
    return {"keys": [import_key(key.jwk).as_dict(private=False) for key in all_keys()]}
