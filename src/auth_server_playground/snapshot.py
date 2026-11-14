"""Export and import the whole state of the playground."""

from authlib.oauth2.rfc7591 import ClientMetadataClaims
from joserfc.errors import JoseError

from .models import SETTINGS_ID
from .models import AuthorizationCode
from .models import Client
from .models import Persona
from .models import Settings
from .models import Token
from .models import db
from .models import is_valid_client_id
from .personas import invalid_claims
from .personas import is_valid_sub
from .settings import InvalidDocument
from .settings import validate_document

SNAPSHOT_VERSION = 1

CLIENT_TIMESTAMPS = ("client_id_issued_at", "client_secret_expires_at")


class SnapshotError(ValueError):
    """The snapshot cannot be imported."""


def export_snapshot():
    """Return the configuration, the personas and the clients.

    The client secrets are included. The secret key is not.
    """
    return {
        "version": SNAPSHOT_VERSION,
        "configuration": db.session.get(Settings, SETTINGS_ID).document,
        "personas": [
            {"sub": p.sub, "claims": p.claims, "picture_svg": p.picture_svg}
            for p in Persona.query.order_by(Persona.id)
        ],
        "clients": [
            {
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "client_id_issued_at": c.client_id_issued_at,
                "client_secret_expires_at": c.client_secret_expires_at,
                "client_metadata": c.client_metadata,
            }
            for c in Client.query.order_by(Client.id)
        ],
    }


def all_unique(values):
    return len(set(values)) == len(values)


def check_snapshot(data):
    """Raise SnapshotError if the snapshot cannot be imported."""
    if not isinstance(data, dict):
        raise SnapshotError("A snapshot is a JSON object.")
    if data.get("version") != SNAPSHOT_VERSION:
        raise SnapshotError(f"Unknown snapshot version: {data.get('version')!r}.")
    for key in ("configuration", "personas", "clients"):
        if key not in data:
            raise SnapshotError(f"The snapshot has no {key!r}.")
    try:
        validate_document(data["configuration"])
    except InvalidDocument as error:
        raise SnapshotError(str(error)) from error
    check_personas(data["personas"])
    check_clients(data["clients"])


def check_personas(personas):
    if not isinstance(personas, list) or not all(
        isinstance(persona, dict) for persona in personas
    ):
        raise SnapshotError("The personas are a list of JSON objects.")
    subs = [persona.get("sub") for persona in personas]
    if not all(is_valid_sub(sub) for sub in subs) or not all_unique(subs):
        raise SnapshotError(
            "Each persona needs its own sub, of at most 255 printable ASCII characters."
        )
    if not all(isinstance(persona.get("claims"), dict) for persona in personas):
        raise SnapshotError("The claims of a persona are a JSON object.")
    for persona in personas:
        if invalid := invalid_claims(persona["claims"]):
            raise SnapshotError(
                f"Persona {persona['sub']!r}: wrong type for {', '.join(invalid)}."
            )
    if not all(
        isinstance(persona.get("picture_svg"), str | None) for persona in personas
    ):
        raise SnapshotError("The picture_svg of a persona is a string.")
    usernames = [
        persona["claims"]["preferred_username"]
        for persona in personas
        if persona["claims"].get("preferred_username")
    ]
    if not all_unique(usernames):
        raise SnapshotError("Each persona needs its own preferred_username.")


def check_clients(clients):
    if not isinstance(clients, list) or not all(
        isinstance(client, dict) for client in clients
    ):
        raise SnapshotError("The clients are a list of JSON objects.")
    client_ids = [client.get("client_id") for client in clients]
    if not all(is_valid_client_id(i) for i in client_ids) or not all_unique(client_ids):
        raise SnapshotError(
            "Each client needs its own client_id, "
            "of 1 to 48 letters, digits, and . _ ~ - characters."
        )
    if not all(
        isinstance(client.get("client_secret"), str | None) for client in clients
    ):
        raise SnapshotError("The client_secret of a client is a string.")
    if not all(
        is_timestamp(client.get(key)) for client in clients for key in CLIENT_TIMESTAMPS
    ):
        raise SnapshotError("The timestamps of a client are integers.")
    for client in clients:
        check_client_metadata(client)


def is_timestamp(value):
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def check_client_metadata(client):
    metadata = client.get("client_metadata")
    if not isinstance(metadata, dict):
        raise SnapshotError("The metadata of a client is a JSON object.")
    try:
        ClientMetadataClaims(metadata, {}).validate()
    except JoseError as error:
        raise SnapshotError(f"Client {client['client_id']!r}: {error}") from error


def snapshot_rows(data):
    """Return the personas and the clients of a checked snapshot, to add to the session."""
    rows = [
        Persona(
            sub=persona["sub"],
            claims=persona["claims"],
            picture_svg=persona.get("picture_svg"),
        )
        for persona in data["personas"]
    ]
    for item in data["clients"]:
        client = Client(
            client_id=item["client_id"],
            client_secret=item.get("client_secret") or "",
            client_id_issued_at=item.get("client_id_issued_at") or 0,
            client_secret_expires_at=item.get("client_secret_expires_at") or 0,
        )
        client.set_client_metadata(item["client_metadata"])
        rows.append(client)
    return rows


def import_snapshot(data):
    """Replace the configuration, the personas and the clients.

    Codes and tokens are deleted. The secret key is kept. Nothing changes
    if the snapshot is not valid.
    """
    check_snapshot(data)
    try:
        for model in (Token, AuthorizationCode, Client, Persona):
            model.query.delete()
        db.session.add_all(snapshot_rows(data))
        row = db.session.get(Settings, SETTINGS_ID)
        row.document = data["configuration"]
        row.revision = Settings.revision + 1
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
