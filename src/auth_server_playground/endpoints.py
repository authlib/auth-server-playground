from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import Blueprint
from flask import abort
from flask import flash
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_babel import gettext as _

from .forms import ConsentForm
from .interaction import current_persona
from .server import get_server
from .server import require_oauth
from .settings import published_metadata
from .store import current_document

bp = Blueprint("oauth", __name__)


def endpoint_urls():
    return {
        "authorization_endpoint": url_for("oauth.authorize", _external=True),
        "token_endpoint": url_for("oauth.issue_token", _external=True),
        "revocation_endpoint": url_for("oauth.revoke_token", _external=True),
    }


def current_metadata(document=None):
    """Return the metadata of the document, with URLs for this request.

    Without a document, use the stored one.
    """
    if document is None:
        document = current_document()
    return published_metadata(document, request.url_root.rstrip("/"), endpoint_urls())


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    persona = current_persona()
    if persona is None:
        return redirect(
            url_for(
                "interaction.select_persona",
                next=request.script_root + request.full_path,
            )
        )

    server = get_server()
    try:
        grant = server.get_consent_grant(end_user=persona)
    except OAuth2Error as error:
        return server.handle_error_response(request, error)

    form = ConsentForm(persona_id=persona.id)
    if request.method == "POST":
        if not form.validate():
            abort(400)
        if form.persona_id.data == persona.id:
            grant_user = persona if form.accept.data else None
            return server.create_authorization_response(
                grant=grant, grant_user=grant_user
            )
        flash(_("The persona changed since this page was shown."), "warning")
        form.persona_id.data = persona.id
    return render_template(
        "interaction/consent.html", form=form, grant=grant, persona=persona
    )


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return get_server().create_token_response()


@bp.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    if not current_document()["settings"]["revocation_enabled"]:
        abort(404)
    return get_server().create_endpoint_response("revocation")


@bp.route("/.well-known/oauth-authorization-server")
def server_metadata():
    return jsonify(current_metadata())


@bp.route("/api/resource")
@require_oauth()
def resource():
    """Return what the access token gives access to."""
    token = current_token
    data = {"scope": token.scope, "client_id": token.client_id}
    if token.persona is not None:
        data["sub"] = token.persona.sub
    return jsonify(data)
