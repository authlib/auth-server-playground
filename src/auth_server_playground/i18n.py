from flask import current_app
from flask import g
from flask import has_request_context
from flask import request
from flask import session
from flask_babel import Babel
from flask_babel import get_locale
from werkzeug.exceptions import NotFound
from werkzeug.routing import BaseConverter

from .interaction import authorization_params

babel = Babel()

#: The blueprint whose URLs start with the language code.
LOCALIZED_BLUEPRINT = "admin"


def available_language_codes():
    return [locale.language for locale in babel.list_translations()]


class LangConverter(BaseConverter):
    """Accept only the language codes that have a translation."""

    regex = r"[a-z]{2,3}"

    def to_python(self, value):
        if value not in available_language_codes():
            raise NotFound(f"Language '{value}' is not available.")
        return value


def requested_language():
    """Return the first interface language in ui_locales, or None.

    ui_locales comes from the authorization request, or from the request in
    the next parameter of the interaction pages.
    """
    values = request.args.get("ui_locales") or authorization_params(
        request.args.get("next")
    ).get("ui_locales", "")
    codes = available_language_codes()
    for tag in values.split():
        language = tag.split("-")[0].lower()
        if language in codes:
            return language
    return None


def preferred_language():
    """Return the language of the URL, else the requested one, else the last one used, else the browser one."""
    return (
        g.get("lang_code")
        or requested_language()
        or session.get("lang_code")
        or request.accept_languages.best_match(available_language_codes())
        or current_app.config["BABEL_DEFAULT_LOCALE"]
    )


def setup_i18n(app):
    @app.url_defaults
    def add_language_code(endpoint, values):
        if not endpoint or not endpoint.startswith(f"{LOCALIZED_BLUEPRINT}."):
            return
        values.setdefault("lang_code", preferred_language())

    @app.url_value_preprocessor
    def pull_lang_code(endpoint, values):
        if not values or "lang_code" not in values:
            return
        g.lang_code = values.pop("lang_code")
        if session.get("lang_code") != g.lang_code:
            session["lang_code"] = g.lang_code

    @app.context_processor
    def language_context():
        return {
            "locale": get_locale(),
            "available_languages": babel.list_translations(),
        }

    def locale_selector():
        if not has_request_context():
            return app.config["BABEL_DEFAULT_LOCALE"]
        return preferred_language()

    app.config.setdefault("BABEL_DEFAULT_LOCALE", "en")
    app.config.setdefault("BABEL_DEFAULT_TIMEZONE", "UTC")
    babel.init_app(app, locale_selector=locale_selector)
    app.url_map.converters["lang"] = LangConverter
    app.jinja_env.policies["ext.i18n.trimmed"] = True
