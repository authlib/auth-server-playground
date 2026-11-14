"""Syntax highlighting of the code shown in the pages."""

import functools

import pygments
from markupsafe import Markup
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name

LIGHT_STYLE = "default"
DARK_STYLE = "github-dark"
SELECTOR = ".highlight"

FORMATTER = HtmlFormatter(nowrap=True)


@functools.cache
def lexer(language):
    return get_lexer_by_name(language)


def highlight(code, language):
    """Return the code as HTML, with a CSS class on each token."""
    html = pygments.highlight(code, lexer(language), FORMATTER)
    # Pygments ends the last line with a newline that the code did not have.
    return Markup(html.removesuffix("\n"))


@functools.cache
def stylesheet():
    """Return the token colors, for the light and the dark color schemes.

    The background comes from Blades.
    """
    light = HtmlFormatter(style=LIGHT_STYLE).get_token_style_defs(SELECTOR)
    dark = HtmlFormatter(style=DARK_STYLE).get_token_style_defs(SELECTOR)
    # Each scheme in its own block, so that no light rule applies in dark mode.
    return "\n".join(
        [
            "@media not (prefers-color-scheme: dark) {",
            *light,
            "}",
            "@media (prefers-color-scheme: dark) {",
            *dark,
            "}",
            "",
        ]
    )
