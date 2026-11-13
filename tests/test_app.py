import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import OperationalError

from auth_server_playground.models import Persona
from auth_server_playground.models import Settings
from auth_server_playground.models import db
from auth_server_playground.store import init_database


def test_secret_key_from_the_environment(monkeypatch, make_app):
    monkeypatch.setenv("SECRET_KEY", "from-env")
    assert make_app().config["SECRET_KEY"] == "from-env"


def test_generated_secret_key_is_shared(monkeypatch, tmp_path, make_app):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    database = f"sqlite:///{tmp_path}/db.sqlite"
    first = make_app(database)
    second = make_app(database)
    assert first.config["SECRET_KEY"]
    assert first.config["SECRET_KEY"] == second.config["SECRET_KEY"]


def test_default_personas_are_created_once(tmp_path, make_app):
    database = f"sqlite:///{tmp_path}/db.sqlite"
    make_app(database)
    app = make_app(database)
    with app.app_context():
        assert Persona.query.count() == 2


def test_tables_created_by_another_worker(monkeypatch, make_app):
    """Another worker may create a table between the check and the creation."""
    calls = []
    create_all = db.create_all

    def flaky_create_all(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("CREATE TABLE", {}, Exception("table exists"))
        return create_all(*args, **kwargs)

    monkeypatch.setattr(db, "create_all", flaky_create_all)
    make_app()
    assert len(calls) == 2


def test_missing_settings_with_existing_personas(tmp_path, make_app):
    database = f"sqlite:///{tmp_path}/db.sqlite"
    app = make_app(database)
    with app.app_context():
        Settings.query.delete()
        db.session.commit()
    with pytest.raises(IntegrityError):
        init_database(app)
