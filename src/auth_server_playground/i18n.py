from flask import g
from flask import has_request_context
from flask import request
from flask import session
from flask_babel import Babel
from flask_babel import get_locale
from werkzeug.exceptions import NotFound
from werkzeug.routing import BaseConverter

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


def setup_i18n(app):
    @app.url_defaults
    def add_language_code(endpoint, values):
        if not endpoint or not endpoint.startswith(f"{LOCALIZED_BLUEPRINT}."):
            return
        values.setdefault(
            "lang_code",
            g.get("lang_code")
            or session.get("lang_code")
            or app.config["BABEL_DEFAULT_LOCALE"],
        )

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
        """Use the language of the URL, else the last one used, else the browser one."""
        if not has_request_context():
            return app.config["BABEL_DEFAULT_LOCALE"]
        return (
            g.get("lang_code")
            or session.get("lang_code")
            or request.accept_languages.best_match(available_language_codes())
            or app.config["BABEL_DEFAULT_LOCALE"]
        )

    app.config.setdefault("BABEL_DEFAULT_LOCALE", "en")
    app.config.setdefault("BABEL_DEFAULT_TIMEZONE", "UTC")
    babel.init_app(app, locale_selector=locale_selector)
    app.url_map.converters["lang"] = LangConverter
    app.jinja_env.policies["ext.i18n.trimmed"] = True
