import json
import secrets
import time

from flask import Blueprint
from flask import flash
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_babel import get_locale
from flask_babel import gettext as _

from .endpoints import current_metadata
from .forms import ActionForm
from .forms import ClientForm
from .forms import ConfirmImportForm
from .forms import ImportForm
from .forms import PersonaForm
from .forms import RandomPersonaForm
from .forms import ServerForm
from .interaction import current_persona
from .models import Client
from .models import Persona
from .models import db
from .personas import create_random_persona
from .personas import random_locale_for
from .personas import render_avatar
from .settings import ENDPOINTS
from .settings import InvalidDocument
from .settings import default_document
from .settings import unsupported_values
from .settings import validate_document
from .snapshot import check_snapshot
from .snapshot import export_snapshot
from .snapshot import import_snapshot
from .store import current_document
from .store import delete_client
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


def client_rows(document):
    """Return each client with the values that the server does not support."""
    return [
        (client, unsupported_values(client.client_metadata, document))
        for client in Client.query.order_by(Client.id)
    ]


@bp.route("/")
def index():
    return render_template(
        "admin/index.html",
        metadata=current_metadata(),
        metadata_url=url_for("oauth.server_metadata", _external=True),
        endpoints=ENDPOINTS,
        client_count=Client.query.count(),
        persona_count=Persona.query.count(),
        warnings=[row for row in client_rows(current_document()) if row[1]],
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


@bp.route("/clients")
def clients():
    return render_template("admin/clients.html", rows=client_rows(current_document()))


@bp.route("/clients/new", methods=["GET", "POST"])
def new_client():
    form = ClientForm(current_document())
    if not form.validate_on_submit():
        return render_template("admin/client.html", form=form, client=None)

    client = form.save_client()
    flash(_("The client is created."), "success")
    return redirect(url_for("admin.edit_client", client_id=client.client_id))


def get_client(client_id):
    return Client.query.filter_by(client_id=client_id).first_or_404()


@bp.route("/clients/<client_id>", methods=["GET", "POST"])
def edit_client(client_id):
    client = get_client(client_id)
    form = ClientForm(current_document(), client)
    if not form.validate_on_submit():
        return render_template(
            "admin/client.html",
            form=form,
            client=client,
            regenerate_form=ActionForm(prefix="regenerate"),
            delete_form=ActionForm(prefix="delete"),
        )

    form.save_client()
    flash(_("The client is saved."), "success")
    return redirect(url_for("admin.edit_client", client_id=client_id))


@bp.route("/clients/<client_id>/secret", methods=["POST"])
def regenerate_secret(client_id):
    client = get_client(client_id)
    if ActionForm(prefix="regenerate").validate_on_submit() and client.client_secret:
        client.client_secret = secrets.token_urlsafe(36)
        db.session.commit()
        flash(_("The client secret is regenerated."), "success")
    return redirect(url_for("admin.edit_client", client_id=client_id))


@bp.route("/clients/<client_id>/delete", methods=["POST"])
def remove_client(client_id):
    client = get_client(client_id)
    if not ActionForm(prefix="delete").validate_on_submit():
        return redirect(url_for("admin.edit_client", client_id=client_id))

    delete_client(client)
    flash(_("The client is deleted."), "success")
    return redirect(url_for("admin.clients"))


@bp.route("/personas")
def personas():
    return render_template(
        "admin/personas.html",
        personas=Persona.query.order_by(Persona.id).all(),
        random_form=RandomPersonaForm(
            prefix="random", locale=random_locale_for(get_locale().language)
        ),
    )


@bp.route("/personas/new", methods=["GET", "POST"])
def new_persona():
    form = PersonaForm()
    if not form.validate_on_submit():
        return render_template("admin/persona.html", form=form, persona=None)

    persona = form.save_persona()
    flash(_("The persona is created."), "success")
    return redirect(url_for("admin.edit_persona", persona_id=persona.id))


@bp.route("/personas/random", methods=["POST"])
def random_persona():
    form = RandomPersonaForm(prefix="random")
    if not form.validate_on_submit():
        return redirect(url_for("admin.personas"))

    persona = create_random_persona(form.locale.data)
    flash(_("A random persona is created."), "success")
    return redirect(url_for("admin.edit_persona", persona_id=persona.id))


def get_persona(persona_id):
    return db.get_or_404(Persona, persona_id)


@bp.route("/personas/<int:persona_id>", methods=["GET", "POST"])
def edit_persona(persona_id):
    persona = get_persona(persona_id)
    form = PersonaForm(persona)
    if not form.validate_on_submit():
        return render_template(
            "admin/persona.html",
            form=form,
            persona=persona,
            avatar_form=ActionForm(prefix="avatar"),
            delete_form=ActionForm(prefix="delete"),
        )

    form.save_persona()
    flash(_("The persona is saved."), "success")
    return redirect(url_for("admin.edit_persona", persona_id=persona_id))


@bp.route("/personas/<int:persona_id>/avatar", methods=["POST"])
def redraw_avatar(persona_id):
    persona = get_persona(persona_id)
    if ActionForm(prefix="avatar").validate_on_submit():
        persona.picture_svg = render_avatar()
        # The picture claim changes with the avatar.
        persona.claims = {**persona.claims, "updated_at": int(time.time())}
        db.session.commit()
    return redirect(url_for("admin.edit_persona", persona_id=persona_id))


@bp.route("/personas/<int:persona_id>/delete", methods=["POST"])
def remove_persona(persona_id):
    persona = get_persona(persona_id)
    if not ActionForm(prefix="delete").validate_on_submit():
        return redirect(url_for("admin.edit_persona", persona_id=persona_id))

    # The cascade of the model deletes the codes and the tokens of the persona.
    db.session.delete(persona)
    db.session.commit()
    flash(_("The persona is deleted."), "success")
    return redirect(url_for("admin.personas"))


@bp.route("/snapshot", methods=["GET", "POST"])
def snapshot():
    form = ImportForm()
    if not form.validate_on_submit():
        return render_template("admin/snapshot.html", form=form)

    try:
        data = json.loads(form.file.data.read())
        check_snapshot(data)
    # SnapshotError, and the JSON and decoding errors, are ValueErrors.
    except (ValueError, RecursionError) as error:
        flash(_("This snapshot cannot be imported: %(error)s", error=error), "error")
        return render_template("admin/snapshot.html", form=form)

    confirm = ConfirmImportForm(data={"snapshot": json.dumps(data)})
    return render_template("admin/snapshot_confirm.html", form=confirm, snapshot=data)


@bp.route("/snapshot/confirm", methods=["POST"])
def confirm_import():
    form = ConfirmImportForm()
    if not form.validate_on_submit():
        return redirect(url_for("admin.snapshot"))

    try:
        import_snapshot(json.loads(form.snapshot.data))
    except (ValueError, RecursionError) as error:
        flash(_("This snapshot cannot be imported: %(error)s", error=error), "error")
    else:
        flash(_("The snapshot is imported."), "success")
    return redirect(url_for("admin.snapshot"))


@bp.route("/snapshot/export")
def export_snapshot_file():
    response = jsonify(export_snapshot())
    response.headers["Content-Disposition"] = (
        "attachment; filename=auth-server-playground-snapshot.json"
    )
    return response
