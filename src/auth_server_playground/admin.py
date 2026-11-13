import json

from flask import Blueprint
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_babel import gettext as _

from .endpoints import current_metadata
from .forms import ActionForm
from .forms import ServerForm
from .interaction import current_persona
from .models import Client
from .models import Persona
from .settings import ENDPOINTS
from .settings import InvalidDocument
from .settings import default_document
from .settings import unsupported_values
from .settings import validate_document
from .store import current_document
from .store import save_document

bp = Blueprint("admin", __name__, url_prefix="/<lang:lang_code>")


@bp.context_processor
def persona_context():
    # A function, so that only the templates that show the persona query it.
    return {"current_persona": current_persona}


@bp.app_template_filter()
def pretty_json(value):
    """Format JSON for reading, keeping the order of the keys."""
    return json.dumps(value, indent=2)


def client_warnings(document):
    """Return the clients with values that the server does not support."""
    warnings = []
    for client in Client.query.order_by(Client.id):
        values = unsupported_values(client.client_metadata, document)
        if values:
            warnings.append((client, values))
    return warnings


@bp.route("/")
def index():
    return render_template(
        "admin/index.html",
        metadata=current_metadata(),
        metadata_url=url_for("oauth.server_metadata", _external=True),
        endpoints=ENDPOINTS,
        client_count=Client.query.count(),
        persona_count=Persona.query.count(),
        warnings=client_warnings(current_document()),
    )


def preview_of(form):
    """Return the metadata the form would publish, and the errors."""
    if not form.validate():
        return None, form.errors
    document = form.to_document()
    try:
        validate_document(document)
    except InvalidDocument as error:
        return None, error.errors
    return current_metadata(document), {}


@bp.route("/server", methods=["GET", "POST"])
def server():
    form = ServerForm.from_document(current_document())
    metadata, errors = current_metadata(), {}
    if form.validate_on_submit():
        try:
            save_document(form.to_document())
        except InvalidDocument as error:
            form.add_document_errors(error.errors)
            metadata, errors = None, error.errors
        else:
            flash(_("The server configuration is saved."), "success")
            return redirect(url_for("admin.server"))
    elif request.method == "POST":
        metadata, errors = None, form.errors

    return render_template(
        "admin/server.html",
        form=form,
        defaults_form=ActionForm(),
        metadata=metadata,
        errors=errors,
    )


@bp.route("/server/preview", methods=["POST"])
def server_preview():
    metadata, errors = preview_of(ServerForm())
    return render_template(
        "admin/_metadata_preview.html", metadata=metadata, errors=errors
    )


@bp.route("/server/defaults", methods=["POST"])
def server_defaults():
    if ActionForm().validate_on_submit():
        save_document(default_document())
        flash(_("The default configuration is restored."), "success")
    return redirect(url_for("admin.server"))
