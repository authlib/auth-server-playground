import copy
import secrets

from sqlalchemy.exc import DatabaseError
from sqlalchemy.exc import IntegrityError

from .models import SETTINGS_ID
from .models import Settings
from .models import db
from .personas import default_personas
from .settings import default_document
from .settings import validate_document


def init_database(app):
    """Create the tables, the settings and the default personas.

    Several workers may run it at the same time on an empty database. The
    settings row has a fixed id, so only one worker can insert it, with the
    default personas in the same transaction.

    Return the stored secret key.
    """
    with app.app_context():
        create_tables()
        db.session.add(
            Settings(
                id=SETTINGS_ID,
                document=default_document(),
                revision=1,
                secret_key=secrets.token_hex(32),
            )
        )
        db.session.add_all(default_personas())
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            # Without the settings, the error has another cause.
            if settings_row() is None:
                raise
        return settings_row().secret_key


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
