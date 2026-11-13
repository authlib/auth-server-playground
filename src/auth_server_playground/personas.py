import time

from .models import Persona

COMPLETE_SUB = "c0a1e3d2-7b5f-4e7a-9d2c-1f6b8a4e5c3d"
MINIMAL_SUB = "5e8d2b1a-3c4f-4a6e-8b7d-9f0e1a2b3c4d"


def default_personas():
    """Return the personas of a new database: one complete, one minimal."""
    now = int(time.time())
    complete = Persona(
        sub=COMPLETE_SUB,
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
