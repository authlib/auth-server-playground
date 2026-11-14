from auth_server_playground import cli
from auth_server_playground.models import db


def test_run(monkeypatch, tmp_path):
    calls = {}

    def run(app, **kwargs):
        calls.update(kwargs)
        with app.app_context():
            db.engine.dispose()

    # load_dotenv reads the .env of the current directory.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/db.sqlite")
    monkeypatch.delenv("FLASK_RUN_HOST", raising=False)
    monkeypatch.setenv("FLASK_RUN_PORT", "5001")
    monkeypatch.setenv("FLASK_DEBUG", "1")
    monkeypatch.setattr("flask.Flask.run", run)
    cli.run()
    assert calls == {"host": "127.0.0.1", "port": 5001, "debug": True}
