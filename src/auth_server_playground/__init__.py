import importlib.metadata
import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from . import endpoints
from . import interaction
from .i18n import setup_i18n
from .models import db
from .routes import bp
from .store import init_database


def is_proxy_fix_enabled():
    """Read from the environment whether the application runs behind a proxy."""
    value = os.environ.get("PROXY_FIX", "").strip().lower()
    if value in ("", "0", "false"):
        return False
    if value in ("1", "true"):
        return True
    raise ValueError(f"PROXY_FIX must be true or false, got {value!r}")


def create_app(config=None):
    """Create the Flask application, configured from the environment."""
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///db.sqlite"
    )
    # Browsers do not send the session cookie with cross-site POST requests,
    # such as a forged consent form.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    if config:
        app.config.update(config)

    if is_proxy_fix_enabled():
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_prefix=1)

    db.init_app(app)
    stored_key = init_database(app)
    # Without SECRET_KEY, all the workers share the key stored in the database.
    app.config["SECRET_KEY"] = (
        app.config.get("SECRET_KEY") or os.environ.get("SECRET_KEY") or stored_key
    )

    setup_app(app)
    return app


def setup_app(app):
    setup_i18n(app)

    @app.context_processor
    def version_context():
        return {
            "app_version": importlib.metadata.version("auth-server-playground"),
            "repository_url": "https://github.com/authlib/auth-server-playground",
        }

    app.register_blueprint(bp)
    app.register_blueprint(endpoints.bp)
    app.register_blueprint(interaction.bp)
