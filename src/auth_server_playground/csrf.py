"""CSRF check of every form, with a message when the token is not valid."""

from flask import flash
from flask import redirect
from flask import request
from flask import url_for
from flask_babel import gettext as _
from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def previous_page():
    """Return the page that sent the request when it is on this host, else the admin home."""
    referrer = request.referrer
    if referrer and referrer.startswith(request.url_root):
        return referrer

    return url_for("admin.index")


def handle_csrf_error(error):
    """Flash that the token is not valid, and redirect to the page of the form."""
    flash(
        _(
            "The form token is not valid. Check that cookies are allowed, then reload the page."
        ),
        "error",
    )
    if "GET" in request.url_rule.methods:
        return redirect(request.url, 303)

    return redirect(previous_page(), 303)


def setup_csrf(app):
    """Check the CSRF token of every POST, PUT, PATCH and DELETE request."""
    # The token lives as long as the session.
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)
    # The token is enough. Browsers may send no Referer over HTTPS.
    app.config.setdefault("WTF_CSRF_SSL_STRICT", False)
    csrf.init_app(app)
    app.register_error_handler(CSRFError, handle_csrf_error)
