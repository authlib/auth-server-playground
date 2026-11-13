from flask import current_app
from flask_babel import lazy_gettext as _
from flask_wtf import FlaskForm
from flask_wtforms_htmx import HtmxFlaskForm
from markupsafe import Markup
from wtforms import BooleanField
from wtforms import ButtonField
from wtforms import HiddenField
from wtforms import IntegerField
from wtforms import RadioField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import URLField
from wtforms.csrf.core import CSRFTokenField
from wtforms.fields import SelectChoice
from wtforms.fields import SelectFieldBase
from wtforms.meta import clean_key
from wtforms.validators import InputRequired
from wtforms.validators import NumberRange
from wtforms.validators import Optional
from wtforms.widgets import CheckboxInput
from wtforms.widgets import HiddenInput
from wtforms.widgets import ListWidget

from .settings import AUTH_METHODS
from .settings import ENDPOINTS
from .settings import GRANT_TYPES
from .settings import MAX_LIFETIME
from .settings import PKCE_METHODS
from .settings import response_types_for

# The render_kw keys that field_wrapper reads, and that are not HTML attributes.
WRAPPER_DEFAULTS = {"group_with": None, "hidden": False, "param": None}

BARE_FIELDS = (
    HiddenField,
    CSRFTokenField,
    SubmitField,
    ButtonField,
)


class BaseForm(HtmxFlaskForm):
    """Form whose fields are rendered through the _field.html template.

    Hidden fields and buttons are rendered bare. A field can declare
    ``render_kw={"group_with": "<button name>"}`` to render that button
    next to its input, and ``render_kw={"param": "<name>"}`` to show the
    protocol parameter it sets after its label.
    """

    class Meta:
        htmx_inline_validation = False

        def render_field(self, field, render_kw):
            # WTForms gives the render_kw of a choices field to each of its
            # options, which are rendered without field_wrapper.
            if isinstance(field, SelectFieldBase._Option) and field.render_kw:
                field.render_kw = {
                    key: value
                    for key, value in field.render_kw.items()
                    if key not in WRAPPER_DEFAULTS
                }
            return super().render_field(field, render_kw)

        def field_wrapper(self, field, render_kw):
            wrapper_kw = {
                key: render_kw.pop(key, default)
                for key, default in WRAPPER_DEFAULTS.items()
            }
            group_with = wrapper_kw["group_with"]
            render_kw = {clean_key(key): value for key, value in render_kw.items()}
            if isinstance(field, BARE_FIELDS):
                return field.widget(field, hidden=wrapper_kw["hidden"], **render_kw)

            field_id = render_kw.get("id", field.id)
            fieldset = isinstance(field.widget, ListWidget)
            error_id = f"{field_id}-error" if field.errors else None
            if error_id and not fieldset:
                render_kw = {
                    **render_kw,
                    "aria-invalid": "true",
                    "aria-describedby": error_id,
                }

            template = current_app.jinja_env.get_template("_field.html")
            return Markup(
                template.render(
                    field=field,
                    render_kw=render_kw,
                    field_id=field_id,
                    fieldset=fieldset,
                    error_id=error_id,
                    hidden=wrapper_kw["hidden"],
                    param=wrapper_kw["param"],
                    button=field._form[group_with] if group_with else None,
                )
            )


class MultiCheckboxField(SelectMultipleField):
    """A list of checkboxes."""

    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()


class SelectPersonaForm(BaseForm):
    persona = RadioField(_("Persona"), coerce=int, validators=[InputRequired()])
    select = SubmitField(_("Continue as this persona"))


class ConsentForm(FlaskForm):
    persona_id = IntegerField(widget=HiddenInput())
    accept = SubmitField(_("Accept"))
    deny = SubmitField(_("Deny"))


class ServerForm(BaseForm):
    issuer = URLField(
        _("Issuer"),
        validators=[Optional()],
        description=_("Leave empty to use the URL of each request."),
        render_kw={"param": "issuer"},
    )
    grant_types_supported = MultiCheckboxField(
        _("Grant types"),
        choices=[SelectChoice(grant, grant) for grant in GRANT_TYPES],
        render_kw={"param": "grant_types_supported"},
    )
    token_endpoint_auth_methods_supported = MultiCheckboxField(
        _("Client authentication methods"),
        choices=[SelectChoice(method, method) for method in AUTH_METHODS],
        render_kw={"param": "token_endpoint_auth_methods_supported"},
    )
    code_challenge_methods_supported = MultiCheckboxField(
        _("PKCE methods"),
        choices=[SelectChoice(method, method) for method in PKCE_METHODS],
        description=_("Leave all unchecked to disable PKCE."),
        render_kw={"param": "code_challenge_methods_supported"},
    )
    pkce_required = RadioField(
        _("PKCE is required for"),
        choices=[
            SelectChoice("all", _("All clients")),
            SelectChoice("public", _("Public clients only")),
        ],
    )
    access_token_lifetime = IntegerField(
        _("Access token lifetime"),
        validators=[InputRequired(), NumberRange(min=1, max=MAX_LIFETIME)],
        description=_("In seconds."),
    )
    refresh_token_lifetime = IntegerField(
        _("Refresh token lifetime"),
        validators=[InputRequired(), NumberRange(min=1, max=MAX_LIFETIME)],
        description=_("In seconds."),
    )
    refresh_token_rotation = BooleanField(
        _("Issue a new refresh token on each refresh"),
        render_kw={"role": "switch"},
    )
    revocation_enabled = BooleanField(
        _("Token revocation endpoint"),
        render_kw={"role": "switch", "param": "revocation_endpoint"},
    )
    scopes_supported = StringField(
        _("Scopes"),
        description=_("Separated by spaces. Leave empty to accept any scope."),
        render_kw={"param": "scopes_supported"},
    )
    save = SubmitField(_("Save"))

    SETTINGS = (
        "pkce_required",
        "access_token_lifetime",
        "refresh_token_lifetime",
        "refresh_token_rotation",
        "revocation_enabled",
    )

    @classmethod
    def from_document(cls, document):
        data = {**document["metadata"], **document["settings"]}
        data["issuer"] = data["issuer"] or ""
        data["scopes_supported"] = " ".join(data["scopes_supported"])
        return cls(data=data)

    def to_document(self):
        grant_types = self.grant_types_supported.data
        return {
            "metadata": {
                "issuer": self.issuer.data or None,
                "scopes_supported": (self.scopes_supported.data or "").split(),
                "response_types_supported": response_types_for(grant_types),
                "grant_types_supported": grant_types,
                "token_endpoint_auth_methods_supported": (
                    self.token_endpoint_auth_methods_supported.data
                ),
                "code_challenge_methods_supported": (
                    self.code_challenge_methods_supported.data
                ),
            },
            "settings": {name: self[name].data for name in self.SETTINGS},
        }

    def add_document_errors(self, errors):
        """Show the errors of the document on their fields, or on the form."""
        for key, message in errors.items():
            # The endpoint URLs are built from the issuer: its own error is enough.
            if key in ENDPOINTS and "issuer" in errors:
                continue
            name = "issuer" if key in ENDPOINTS else key
            if name in self._fields:
                self[name].errors = [*self[name].errors, message]
            else:
                self.form_errors.append(message)


class ActionForm(FlaskForm):
    """A form with only a CSRF token, for the buttons that change data."""

    submit = SubmitField()
