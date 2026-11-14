import re
import time

from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from flask import url_for
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

#: The id of the single row of the settings table.
SETTINGS_ID = 1


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    document = db.Column(db.JSON, nullable=False)
    revision = db.Column(db.Integer, nullable=False, default=1)
    secret_key = db.Column(db.String(64), nullable=False)


class Persona(db.Model):
    __tablename__ = "persona"
    # SQLite reuses the id of a deleted row without it. A browser session
    # that still holds that id would then act as another persona.
    __table_args__ = {"sqlite_autoincrement": True}

    id = db.Column(db.Integer, primary_key=True)
    sub = db.Column(db.String(255), unique=True, nullable=False)
    claims = db.Column(db.JSON, nullable=False, default=dict)
    picture_svg = db.Column(db.Text)

    codes = db.relationship(
        "AuthorizationCode", back_populates="persona", cascade="all, delete-orphan"
    )
    tokens = db.relationship(
        "Token", back_populates="persona", cascade="all, delete-orphan"
    )

    def __str__(self):
        return self.claims.get("name") or self.preferred_username or self.sub

    @property
    def preferred_username(self):
        return self.claims.get("preferred_username")

    @property
    def picture_url(self):
        """Return the picture claim: the stored URL, else the generated avatar, if any."""
        if self.claims.get("picture"):
            return self.claims["picture"]
        if self.picture_svg:
            return url_for("oauth.persona_picture", persona_id=self.id, _external=True)
        return None


#: Characters that need no escaping in a URL path (RFC 3986 §2.3).
CLIENT_ID_PATTERN = re.compile(r"[A-Za-z0-9._~-]{1,48}")
RESERVED_CLIENT_IDS = ("new", ".", "..")


def is_valid_client_id(value):
    """Return whether the client_id can be a segment of the admin URLs."""
    return (
        isinstance(value, str)
        and CLIENT_ID_PATTERN.fullmatch(value) is not None
        and value not in RESERVED_CLIENT_IDS
    )


class Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "client"

    id = db.Column(db.Integer, primary_key=True)


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "authorization_code"

    id = db.Column(db.Integer, primary_key=True)
    persona_id = db.Column(db.Integer, db.ForeignKey("persona.id"), nullable=False)
    persona = db.relationship("Persona", back_populates="codes")


class Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "token"

    id = db.Column(db.Integer, primary_key=True)
    # Tokens of the client credentials grant have no persona.
    persona_id = db.Column(db.Integer, db.ForeignKey("persona.id"))
    persona = db.relationship("Persona", back_populates="tokens")
    refresh_token_expires_at = db.Column(db.Integer)

    def is_refresh_token_active(self):
        if self.refresh_token_revoked_at:
            return False
        return self.refresh_token_expires_at >= time.time()
