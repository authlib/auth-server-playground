import re
import secrets
import time
import unicodedata
import uuid

import python_avatars
from faker import Faker

from .models import Persona
from .models import db

#: The Faker locales offered for random personas, with their time zone.
RANDOM_LOCALES = {
    "en_US": "America/New_York",
    "fr_FR": "Europe/Paris",
    "de_DE": "Europe/Berlin",
    "es_ES": "Europe/Madrid",
    "pt_BR": "America/Sao_Paulo",
    "ja_JP": "Asia/Tokyo",
}

COMPLETE_SUB = "c0a1e3d2-7b5f-4e7a-9d2c-1f6b8a4e5c3d"
MINIMAL_SUB = "5e8d2b1a-3c4f-4a6e-8b7d-9f0e1a2b3c4d"

#: The standard claims (OIDC Core §5.1), and the members of the address claim.
STANDARD_CLAIMS = (
    "sub",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
)
ADDRESS_FIELDS = (
    "formatted",
    "street_address",
    "locality",
    "region",
    "postal_code",
    "country",
)

#: The types of the standard claims.
STRING_CLAIMS = (
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
)
BOOLEAN_CLAIMS = ("email_verified", "phone_number_verified")


def invalid_claims(claims):
    """Return the standard claims whose value has the wrong type."""
    invalid = [
        key
        for key in STRING_CLAIMS
        if key in claims and not isinstance(claims[key], str)
    ]
    invalid += [
        key
        for key in BOOLEAN_CLAIMS
        if key in claims and not isinstance(claims[key], bool)
    ]
    updated_at = claims.get("updated_at")
    if "updated_at" in claims and (
        not isinstance(updated_at, int) or isinstance(updated_at, bool)
    ):
        invalid.append("updated_at")
    address = claims.get("address")
    if "address" in claims and not (
        isinstance(address, dict)
        and all(isinstance(value, str) for value in address.values())
    ):
        invalid.append("address")
    return invalid


def is_valid_sub(value):
    """Per OIDC Core §2, a sub is at most 255 ASCII characters."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= 255
        and value.isascii()
        and value.isprintable()
    )


def default_personas():
    """Return the personas of a new database: one complete, one minimal."""
    now = int(time.time())
    complete = Persona(
        sub=COMPLETE_SUB,
        picture_svg=render_avatar(),
        claims={
            "name": "Alice Martin",
            "given_name": "Alice",
            "family_name": "Martin",
            "middle_name": "Claire",
            "nickname": "Ali",
            "preferred_username": "alice",
            "profile": "https://alice.example/profile",
            "website": "https://alice.example",
            "email": "alice@example.com",
            "email_verified": True,
            "gender": "female",
            "birthdate": "1990-12-10",
            "zoneinfo": "Europe/Paris",
            "locale": "fr-FR",
            "phone_number": "+33 1 23 45 67 89",
            "phone_number_verified": True,
            "address": {
                "formatted": "1 rue de la Paix\n75002 Paris\nFrance",
                "street_address": "1 rue de la Paix",
                "locality": "Paris",
                "region": "Île-de-France",
                "postal_code": "75002",
                "country": "France",
            },
            "updated_at": now,
        },
    )
    # Missing claims are left out, not returned as null (OpenID Connect Core §5.3.2).
    minimal = Persona(
        sub=MINIMAL_SUB,
        claims={
            "preferred_username": "bob",
            "email": "bob@example.com",
            "email_verified": False,
            "updated_at": now,
        },
    )
    return [complete, minimal]


def find_by_username(username):
    return Persona.query.filter(
        Persona.claims["preferred_username"].as_string() == username
    ).first()


def render_avatar():
    return python_avatars.Avatar.random().render()


def random_locale_for(language):
    """Return the Faker locale of the random personas for an interface language."""
    for locale in RANDOM_LOCALES:
        if locale.startswith(f"{language}_"):
            return locale
    return "en_US"


def create_random_persona(locale):
    """Create a random persona in the database, and return it."""
    persona = random_persona(locale)
    db.session.add(persona)
    db.session.commit()
    return persona


def username_from(given_name, family_name):
    """Return a lower case ASCII username built from the names, maybe empty."""
    text = unicodedata.normalize("NFKD", f"{given_name[:1]}{family_name}")
    return re.sub(r"[^a-z0-9]", "", text.encode("ascii", "ignore").decode().lower())


def unique_username(username):
    candidate = username
    while find_by_username(candidate) is not None:
        candidate = f"{username}{secrets.randbelow(10000)}"
    return candidate


def random_persona(locale):
    """Return a persona with all the standard claims, from a Faker locale."""
    fake = Faker(locale)
    female = fake.boolean()
    first_name = fake.first_name_female if female else fake.first_name_male
    given_name = first_name()
    family_name = fake.last_name()
    # Names in other scripts give no ASCII username: Faker makes one instead.
    username = unique_username(
        username_from(given_name, family_name) or fake.user_name()
    )
    street = fake.street_address()
    locality = fake.city()
    postal_code = fake.postcode()
    country = fake.current_country()
    return Persona(
        sub=str(uuid.uuid4()),
        picture_svg=render_avatar(),
        claims={
            "name": f"{given_name} {family_name}",
            "given_name": given_name,
            "family_name": family_name,
            "middle_name": first_name(),
            "nickname": given_name,
            "preferred_username": username,
            "profile": f"https://{username}.example/profile",
            "website": f"https://{username}.example",
            # example.com is reserved for documentation (RFC 2606).
            "email": f"{username}@example.com",
            "email_verified": True,
            "gender": "female" if female else "male",
            "birthdate": fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
            "zoneinfo": RANDOM_LOCALES[locale],
            "locale": locale.replace("_", "-"),
            "phone_number": fake.phone_number(),
            "phone_number_verified": fake.boolean(),
            "address": {
                "formatted": f"{street}\n{postal_code} {locality}\n{country}",
                "street_address": street,
                "locality": locality,
                "postal_code": postal_code,
                "country": country,
            },
            "updated_at": int(time.time()),
        },
    )
