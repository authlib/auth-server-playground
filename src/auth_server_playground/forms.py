from flask import current_app
from flask_wtforms_htmx import HtmxFlaskForm
from markupsafe import Markup
from wtforms import ButtonField
from wtforms import HiddenField
from wtforms import SelectMultipleField
from wtforms import SubmitField
from wtforms.csrf.core import CSRFTokenField
from wtforms.fields import SelectFieldBase
from wtforms.meta import clean_key
from wtforms.widgets import CheckboxInput
from wtforms.widgets import ListWidget

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
