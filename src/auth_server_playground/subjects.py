"""The subject identifiers of the personas (OIDC Core §8)."""

import base64
import hashlib
from urllib.parse import urlsplit

from .models import SETTINGS_ID
from .models import Settings
from .models import db


class ClientPersona:
    """A persona, with the client that the authorization is for.

    Authlib passes only the user to generate_user_info. A pairwise sub
    also needs the client.
    """

    def __init__(self, persona, client):
        self.persona = persona
        self.client = client

    @property
    def id(self):
        return self.persona.id


def sector_of(metadata):
    """Return the host of sector_identifier_uri, else of the first redirect URI."""
    uris = [metadata.get("sector_identifier_uri"), *metadata.get("redirect_uris", [])]
    uri = next((uri for uri in uris if uri), "")
    return urlsplit(uri).hostname or ""


def pairwise_sub(sector, sub, salt):
    """Per OIDC Core §8.1, hash the sector, the local sub and a salt."""
    digest = hashlib.sha256(f"{sector}{sub}{salt}".encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def subject_for(persona, client):
    """Return the sub of the persona for the client.

    Per OIDC Registration §2, the server picks the subject type of a client
    without one: pairwise when the server does not list public.
    """
    if client is None:
        return persona.sub

    document = db.session.get(Settings, SETTINGS_ID).document
    subject_type = client.client_metadata.get("subject_type")
    if subject_type is None:
        listed = document["metadata"]["subject_types_supported"]
        subject_type = "public" if "public" in listed else "pairwise"

    if subject_type != "pairwise":
        return persona.sub

    salt = document["settings"]["pairwise_salt"]
    return pairwise_sub(sector_of(client.client_metadata), persona.sub, salt)
