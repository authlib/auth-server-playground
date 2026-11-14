import datetime
import functools
import json
import re
import secrets
import time
import uuid
import zoneinfo
from urllib.parse import urlsplit

from babel import localedata
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
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms import URLField
from wtforms import ValidationError
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

from .models import Client
from .models import Persona
from .models import db
from .personas import RANDOM_LOCALES
from .personas import find_by_username
from .personas import render_avatar
from .settings import AUTH_METHODS
from .settings import ENDPOINTS
from .settings import GRANT_TYPES
from .settings import MAX_LIFETIME
from .settings import PKCE_METHODS
from .settings import RESPONSE_TYPES
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


def lines(text):
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


#: Characters that need no escaping in a URL path (RFC 3986 §2.3).
CLIENT_ID_PATTERN = re.compile(r"[A-Za-z0-9._~-]{1,48}")
RESERVED_CLIENT_IDS = ("new", ".", "..")


def is_web_url(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def check_url(form, field):
    if field.data and not is_web_url(field.data):
        raise ValidationError(_("This is not an http or https URL."))


def check_urls(form, field):
    for url in lines(field.data):
        # Redirection endpoints have no fragment (RFC 6749 §3.1.2).
        if not is_web_url(url) or "#" in url:
            raise ValidationError(
                _(
                    "Each line must be an http or https URL without fragment: %(url)s",
                    url=url,
                )
            )


def with_stored(values, stored):
    """Return the known values, followed by the stored values that are unknown."""
    return [*values, *(value for value in stored if value not in values)]


def marked_choices(values, supported):
    """Return the choices, marking the values that the server does not support."""
    return [
        SelectChoice(
            value,
            value
            if value in supported
            else Markup("{} <mark>{}</mark>").format(
                value, _("not supported by the server")
            ),
        )
        for value in values
    ]


class ClientForm(BaseForm):
    client_id = StringField(
        _("Client ID"),
        description=_("Leave empty to generate one. Letters, digits, and . _ ~ -"),
        filters=[lambda value: value.strip() if value else value],
        render_kw={"param": "client_id"},
    )
    client_name = StringField(_("Name"), render_kw={"param": "client_name"})
    client_uri = URLField(
        _("Home page"), validators=[check_url], render_kw={"param": "client_uri"}
    )
    logo_uri = URLField(
        _("Logo"), validators=[check_url], render_kw={"param": "logo_uri"}
    )
    redirect_uris = TextAreaField(
        _("Redirect URIs"),
        validators=[check_urls],
        description=_("One per line."),
        render_kw={"param": "redirect_uris", "rows": 3},
    )
    grant_types = MultiCheckboxField(
        _("Grant types"), render_kw={"param": "grant_types"}
    )
    response_types = MultiCheckboxField(
        _("Response types"), render_kw={"param": "response_types"}
    )
    scope = StringField(_("Scopes"), render_kw={"param": "scope"})
    token_endpoint_auth_method = SelectField(
        _("Authentication method"),
        render_kw={"param": "token_endpoint_auth_method"},
    )
    contacts = TextAreaField(
        _("Contacts"),
        description=_("One per line."),
        render_kw={"param": "contacts", "rows": 2},
    )
    tos_uri = URLField(
        _("Terms of service"), validators=[check_url], render_kw={"param": "tos_uri"}
    )
    policy_uri = URLField(
        _("Privacy policy"),
        validators=[check_url],
        render_kw={"param": "policy_uri"},
    )
    save = SubmitField(_("Save"))

    TEXT_METADATA = (
        "client_name",
        "client_uri",
        "logo_uri",
        "scope",
        "token_endpoint_auth_method",
        "tos_uri",
        "policy_uri",
    )

    def __init__(self, document, client=None, **kwargs):
        if client is not None:
            data = dict(client.client_metadata)
            data["redirect_uris"] = "\n".join(data.get("redirect_uris", []))
            data["contacts"] = "\n".join(data.get("contacts", []))
            kwargs["data"] = data
        super().__init__(**kwargs)
        self.client = client
        if client is not None:
            del self.client_id

        # Values stored by an import or another tool stay available.
        stored = client.client_metadata if client is not None else {}
        metadata = document["metadata"]
        self.grant_types.choices = marked_choices(
            with_stored(GRANT_TYPES, stored.get("grant_types", [])),
            metadata["grant_types_supported"],
        )
        self.response_types.choices = marked_choices(
            with_stored(
                list(RESPONSE_TYPES.values()), stored.get("response_types", [])
            ),
            metadata["response_types_supported"],
        )
        methods = with_stored(
            AUTH_METHODS, [client.token_endpoint_auth_method] if client else []
        )
        # A select option holds text only, so the mark is written out.
        self.token_endpoint_auth_method.choices = [
            SelectChoice(
                method,
                method
                if method in metadata["token_endpoint_auth_methods_supported"]
                else _("%(value)s (not supported by the server)", value=method),
            )
            for method in methods
        ]

    def validate_client_id(self, field):
        if not field.data:
            return
        if (
            not CLIENT_ID_PATTERN.fullmatch(field.data)
            or field.data in RESERVED_CLIENT_IDS
        ):
            raise ValidationError(
                _("Use 1 to 48 letters, digits, and . _ ~ - characters.")
            )
        if Client.query.filter_by(client_id=field.data).count():
            raise ValidationError(_("A client already uses this ID."))

    def client_metadata(self):
        """Return the metadata of the client, updated with the form.

        The metadata the form has no field for are kept.
        """
        metadata = dict(self.client.client_metadata) if self.client else {}
        for name in self.TEXT_METADATA:
            metadata.pop(name, None)
            if self[name].data:
                metadata[name] = self[name].data
        metadata["redirect_uris"] = lines(self.redirect_uris.data)
        metadata["contacts"] = lines(self.contacts.data)
        metadata["grant_types"] = self.grant_types.data
        metadata["response_types"] = self.response_types.data
        return metadata

    def save_client(self):
        """Create or update the client, and return it."""
        client = self.client
        if client is None:
            client = Client(
                client_id=self.client_id.data or secrets.token_urlsafe(18),
                client_id_issued_at=int(time.time()),
            )
            db.session.add(client)
        client.set_client_metadata(self.client_metadata())
        if client.token_endpoint_auth_method == "none":
            client.client_secret = ""
        elif not client.client_secret:
            client.client_secret = secrets.token_urlsafe(36)
        db.session.commit()
        return client


STANDARD_CLAIMS = (
    "sub",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
)
ADDRESS_FIELDS = (
    "formatted",
    "street_address",
    "locality",
    "region",
    "postal_code",
    "country",
)


#: The forms of a birthdate: a full date, a year, or a day without year (OIDC Core §5.1).
BIRTHDATE_PATTERN = re.compile(r"\d{4}(-\d{2}-\d{2})?")


def optional_choices(values):
    return [SelectChoice("", "—"), *(SelectChoice(value, value) for value in values)]


@functools.cache
def time_zones():
    return sorted(zoneinfo.available_timezones())


@functools.cache
def locales():
    return sorted(tag.replace("_", "-") for tag in localedata.locale_identifiers())


def check_birthdate(form, field):
    if not field.data:
        return
    if not BIRTHDATE_PATTERN.fullmatch(field.data):
        raise ValidationError(_("Use YYYY-MM-DD, YYYY or 0000-MM-DD."))
    if len(field.data) == 4:
        return
    # 0000 is the year of a birthdate without year. 2000 accepts 29 February.
    year = "2000" if field.data.startswith("0000") else field.data[:4]
    try:
        datetime.date.fromisoformat(year + field.data[4:])
    except ValueError:
        raise ValidationError(_("This date does not exist.")) from None


class PersonaForm(BaseForm):
    sub = StringField(
        _("Subject"),
        description=_("Leave empty to generate one."),
        filters=[lambda value: value.strip() if value else value],
        render_kw={"param": "sub"},
    )
    name = StringField(_("Full name"), render_kw={"param": "name"})
    preferred_username = StringField(
        _("Username"), render_kw={"param": "preferred_username"}
    )
    given_name = StringField(_("Given name"), render_kw={"param": "given_name"})
    family_name = StringField(_("Family name"), render_kw={"param": "family_name"})
    middle_name = StringField(_("Middle name"), render_kw={"param": "middle_name"})
    nickname = StringField(_("Nickname"), render_kw={"param": "nickname"})
    gender = StringField(_("Gender"), render_kw={"param": "gender"})
    birthdate = StringField(
        _("Birth date"),
        validators=[check_birthdate],
        description=_("YYYY-MM-DD, YYYY or 0000-MM-DD."),
        render_kw={"param": "birthdate"},
    )
    profile = URLField(
        _("Profile page"), validators=[check_url], render_kw={"param": "profile"}
    )
    website = URLField(
        _("Website"), validators=[check_url], render_kw={"param": "website"}
    )
    picture = URLField(
        _("Picture"),
        validators=[check_url],
        description=_("Leave empty to use the generated avatar."),
        render_kw={"param": "picture"},
    )
    email = StringField(_("Email"), render_kw={"param": "email"})
    email_verified = BooleanField(
        _("Email verified"), render_kw={"param": "email_verified"}
    )
    phone_number = StringField(_("Phone number"), render_kw={"param": "phone_number"})
    phone_number_verified = BooleanField(
        _("Phone number verified"), render_kw={"param": "phone_number_verified"}
    )
    zoneinfo = SelectField(_("Time zone"), render_kw={"param": "zoneinfo"})
    locale = SelectField(_("Locale"), render_kw={"param": "locale"})
    address_formatted = TextAreaField(
        _("Formatted address"), render_kw={"param": "formatted", "rows": 3}
    )
    address_street_address = TextAreaField(
        _("Street address"), render_kw={"param": "street_address", "rows": 2}
    )
    address_locality = StringField(_("Locality"), render_kw={"param": "locality"})
    address_region = StringField(_("Region"), render_kw={"param": "region"})
    address_postal_code = StringField(
        _("Postal code"), render_kw={"param": "postal_code"}
    )
    address_country = StringField(_("Country"), render_kw={"param": "country"})
    extra_claims = TextAreaField(
        _("Other claims"),
        description=_("A JSON object. Standard claims have their own field."),
        render_kw={"rows": 4},
    )
    save = SubmitField(_("Save"))

    STRING_CLAIMS = (
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "gender",
        "zoneinfo",
        "locale",
        "phone_number",
    )

    def __init__(self, persona=None, **kwargs):
        if persona is not None and "data" not in kwargs:
            kwargs["data"] = self.persona_data(persona)
        super().__init__(**kwargs)
        self.persona = persona
        self.zoneinfo.choices = optional_choices(time_zones())
        self.locale.choices = optional_choices(locales())

    @staticmethod
    def persona_data(persona):
        claims = dict(persona.claims)
        data = {key: claims.pop(key, None) for key in STANDARD_CLAIMS}
        data["sub"] = persona.sub
        for key in ADDRESS_FIELDS:
            data[f"address_{key}"] = (data.get("address") or {}).get(key)
        data.pop("address")
        data["extra_claims"] = json.dumps(claims, indent=2) if claims else ""
        return data

    def validate_sub(self, field):
        if not field.data:
            return
        # At most 255 ASCII characters (OIDC Core §2).
        if len(field.data) > 255 or not (
            field.data.isascii() and field.data.isprintable()
        ):
            raise ValidationError(_("Use at most 255 printable ASCII characters."))
        existing = Persona.query.filter_by(sub=field.data).first()
        if existing is not None and existing is not self.persona:
            raise ValidationError(_("A persona already uses this subject."))

    def validate_preferred_username(self, field):
        existing = find_by_username(field.data) if field.data else None
        if existing is not None and existing is not self.persona:
            raise ValidationError(_("A persona already uses this username."))

    def validate_extra_claims(self, field):
        try:
            claims = json.loads(field.data.strip() or "{}")
        except json.JSONDecodeError as error:
            raise ValidationError(str(error)) from None
        if not isinstance(claims, dict):
            raise ValidationError(_("The claims must be a JSON object."))
        standard = sorted(set(claims) & set(STANDARD_CLAIMS))
        if standard:
            raise ValidationError(
                _(
                    "These standard claims have their own field: %(claims)s",
                    claims=", ".join(standard),
                )
            )

    def to_claims(self):
        """Return the claims of the form. Empty values are left out."""
        claims = json.loads(self.extra_claims.data.strip() or "{}")
        for name in self.STRING_CLAIMS:
            if self[name].data:
                claims[name] = self[name].data
        if self.birthdate.data:
            claims["birthdate"] = self.birthdate.data
        if self.email.data:
            claims["email_verified"] = self.email_verified.data
        if self.phone_number.data:
            claims["phone_number_verified"] = self.phone_number_verified.data
        # Keep the address members that the form has no field for.
        stored = self.persona.claims.get("address", {}) if self.persona else {}
        address = {
            key: value for key, value in stored.items() if key not in ADDRESS_FIELDS
        }
        address.update(
            {
                key: self[f"address_{key}"].data
                for key in ADDRESS_FIELDS
                if self[f"address_{key}"].data
            }
        )
        if address:
            claims["address"] = address
        claims["updated_at"] = int(time.time())
        return claims

    def save_persona(self):
        """Create or update the persona, and return it."""
        persona = self.persona
        if persona is None:
            persona = Persona(picture_svg=render_avatar())
            db.session.add(persona)
        persona.sub = self.sub.data or str(uuid.uuid4())
        persona.claims = self.to_claims()
        db.session.commit()
        return persona


class RandomPersonaForm(FlaskForm):
    locale = SelectField(
        _("Locale"),
        choices=[SelectChoice(locale, locale) for locale in RANDOM_LOCALES],
    )
    create = SubmitField(_("Random persona"))
