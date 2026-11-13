import time

import pytest
from flask_webtest import TestApp

from auth_server_playground import create_app
from auth_server_playground.models import Client
from auth_server_playground.models import Persona
from auth_server_playground.models import db
from auth_server_playground.personas import COMPLETE_SUB
from auth_server_playground.personas import MINIMAL_SUB
from auth_server_playground.store import current_document
from auth_server_playground.store import save_document
from tests.utils import REDIRECT_URI
from tests.utils import select_persona


@pytest.fixture
def proxy_fix():
    """Return whether the application runs behind a reverse proxy."""
    return False


@pytest.fixture
def insecure_transport():
    """Return whether Authlib accepts plain HTTP requests."""
    return True


@pytest.fixture
def make_app(monkeypatch, proxy_fix, insecure_transport):
    """Create applications, and close their database at the end of the test."""
    monkeypatch.setenv("PROXY_FIX", str(proxy_fix))
    if insecure_transport:
        monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "1")
    else:
        monkeypatch.delenv("AUTHLIB_INSECURE_TRANSPORT", raising=False)

    apps = []

    def make(database="sqlite://", **config):
        app = create_app(
            {"TESTING": True, "SQLALCHEMY_DATABASE_URI": database, **config}
        )
        apps.append(app)
        return app

    yield make

    for app in apps:
        with app.app_context():
            db.engine.dispose()


@pytest.fixture
def app(make_app):
    return make_app(SECRET_KEY="test-secret-key")


@pytest.fixture
def testapp(app):
    return TestApp(app)


@pytest.fixture
def configure(app):
    """Change the server configuration, as the admin page would."""

    def configure(metadata=None, settings=None):
        with app.app_context():
            document = current_document()
            document["metadata"].update(metadata or {})
            document["settings"].update(settings or {})
            save_document(document)

    return configure


@pytest.fixture
def legacy_grants(configure):
    """Enable the implicit and password grants, off by default per RFC 9700."""
    configure(
        metadata={
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "password",
                "client_credentials",
                "refresh_token",
            ],
            "response_types_supported": ["code", "token"],
        }
    )


def persona_dict(persona):
    return {
        "id": persona.id,
        "sub": persona.sub,
        "preferred_username": persona.preferred_username,
    }


@pytest.fixture
def persona(app):
    """Return the complete default persona."""
    with app.app_context():
        return persona_dict(Persona.query.filter_by(sub=COMPLETE_SUB).one())


@pytest.fixture
def other_persona(app):
    """Return the minimal default persona."""
    with app.app_context():
        return persona_dict(Persona.query.filter_by(sub=MINIMAL_SUB).one())


@pytest.fixture
def logged_in(testapp, persona):
    """Select the persona in the test application session."""
    select_persona(testapp, persona)
    return testapp


def make_client(app, *, client_id, client_secret, metadata):
    with app.app_context():
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=int(time.time()),
        )
        client.set_client_metadata(
            {
                "client_name": "Test client",
                "redirect_uris": [REDIRECT_URI],
                "scope": "profile",
                **metadata,
            }
        )
        db.session.add(client)
        db.session.commit()
    return {"client_id": client_id, "client_secret": client_secret}


@pytest.fixture
def client(app):
    """Confidential client for every grant except the implicit one."""
    return make_client(
        app,
        client_id="confidential-client",
        client_secret="confidential-secret",
        metadata={
            "grant_types": [
                "authorization_code",
                "password",
                "client_credentials",
                "refresh_token",
            ],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )


@pytest.fixture
def public_client(app):
    """Public client, without a secret."""
    return make_client(
        app,
        client_id="public-client",
        client_secret="",
        metadata={
            "grant_types": ["authorization_code", "implicit"],
            "response_types": ["code", "token"],
            "token_endpoint_auth_method": "none",
        },
    )
