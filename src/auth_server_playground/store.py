import copy
import json
import secrets

from sqlalchemy.exc import DatabaseError
from sqlalchemy.exc import IntegrityError

from .models import SETTINGS_ID
from .models import AuthorizationCode
from .models import Settings
from .models import Token
from .models import db
from .personas import default_personas
from .settings import default_document
from .settings import validate_document
from .snapshot import check_snapshot
from .snapshot import snapshot_rows


def init_database(app, initial_snapshot=None):
    """Create the tables, the settings and the default personas.

    With an initial snapshot file, an empty database gets its content
    instead of the defaults. The file is checked even if the database is
    not empty.

    Several workers may run it at the same time on an empty database. The
    settings row has a fixed id, so only one worker can insert it, with the
    personas and clients in the same transaction.

    Return the stored secret key.
    """
    snapshot = read_snapshot(initial_snapshot) if initial_snapshot else None
    with app.app_context():
        create_tables()
        db.session.add(
            Settings(
                id=SETTINGS_ID,
                document=snapshot["configuration"] if snapshot else default_document(),
                revision=1,
                secret_key=secrets.token_hex(32),
            )
        )
        db.session.add_all(snapshot_rows(snapshot) if snapshot else default_personas())
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            # Without the settings, the error has another cause.
            if settings_row() is None:
                raise
        return settings_row().secret_key


def read_snapshot(path):
    with open(path, encoding="utf-8") as file:
        snapshot = json.load(file)
    check_snapshot(snapshot)
    return snapshot


def create_tables():
    try:
        db.create_all()
    except DatabaseError:
        # Another worker created a table at the same time.
        db.session.rollback()
        db.create_all()


def settings_row():
    return db.session.get(Settings, SETTINGS_ID)


def current_document():
    """Return a copy of the document, that the caller may change."""
    return copy.deepcopy(settings_row().document)


def save_document(document):
    """Validate and store the document. The server is rebuilt on the next request."""
    validate_document(document)
    row = settings_row()
    row.document = copy.deepcopy(document)
    # Computed by the database, so that two saves at the same time do not
    # write the same revision.
    row.revision = Settings.revision + 1
    db.session.commit()


def delete_client(client):
    """Delete the client with its codes and tokens."""
    AuthorizationCode.query.filter_by(client_id=client.client_id).delete()
    Token.query.filter_by(client_id=client.client_id).delete()
    db.session.delete(client)
    db.session.commit()
