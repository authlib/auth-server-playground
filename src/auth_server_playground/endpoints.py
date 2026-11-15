from urllib.parse import urlencode

from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import Blueprint
from flask import Response
from flask import abort
from flask import flash
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_babel import gettext as _

from .forms import ConsentForm
from .interaction import PlaygroundSession
from .interaction import current_persona
from .interaction import grant_consent
from .keys import public_jwks
from .models import Persona
from .models import db
from .server import get_server
from .server import issuer_for
from .server import require_oauth
from .settings import is_oidc_enabled
from .settings import published_metadata
from .store import current_document

bp = Blueprint("oauth", __name__)

#: The fields of the consent form. An authorization request has none of them.
CONSENT_FIELDS = {"csrf_token", "persona_id", "accept", "deny"}


def endpoint_urls():
    return {
        "authorization_endpoint": url_for("oauth.authorize", _external=True),
        "token_endpoint": url_for("oauth.issue_token", _external=True),
        "revocation_endpoint": url_for("oauth.revoke_token", _external=True),
        "userinfo_endpoint": url_for("oauth.userinfo", _external=True),
        "jwks_uri": url_for("oauth.jwks", _external=True),
    }


def current_metadata(document=None):
    """Return the metadata of the document, with URLs for this request.

    Without a document, use the stored one.
    """
    if document is None:
        document = current_document()
    issuer = issuer_for(document["metadata"]["issuer"])
    return published_metadata(document, issuer, endpoint_urls())


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    # Per OIDC Core §3.1.2.1, the request may come as a POST. The selector
    # and the consent form need its parameters in the URL.
    if request.method == "POST" and not CONSENT_FIELDS & request.form.keys():
        query = urlencode(list(request.values.items(multi=True)))
        return redirect(f"{url_for('oauth.authorize')}?{query}", 303)

    persona = current_persona()
    server = get_server()
    try:
        grant = server.get_consent_grant(session=PlaygroundSession(persona, session))
    except OAuth2Error as error:
        return server.handle_error_response(request, error)

    # Authlib stores the start time of the request before the selector, so
    # that a selection after it counts as a new login.
    if {"login", "select_account"} & set(grant.interactions):
        return redirect(
            url_for(
                "interaction.select_persona",
                next=request.script_root + request.full_path,
            )
        )

    form = ConsentForm(persona_id=persona.id)
    if request.method == "POST":
        if not form.validate():
            abort(400)
        if form.persona_id.data == persona.id:
            if not form.accept.data:
                return server.create_authorization_response(grant=grant)
            grant_consent(persona, grant.client.client_id, grant.request.scope)
            return server.create_authorization_response(grant=grant, grant_user=persona)
        flash(_("The persona changed since this page was shown."), "warning")
        form.persona_id.data = persona.id
    elif "consent" not in grant.interactions:
        return server.create_authorization_response(grant=grant, grant_user=persona)
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


@bp.route("/oauth/userinfo", methods=["GET", "POST"])
def userinfo():
    if not is_oidc_enabled(current_document()):
        abort(404)
    return get_server().create_endpoint_response("userinfo")


@bp.route("/.well-known/oauth-authorization-server")
def server_metadata():
    return jsonify(current_metadata())


@bp.route("/.well-known/openid-configuration")
def openid_configuration():
    document = current_document()
    if not is_oidc_enabled(document):
        abort(404)
    return jsonify(current_metadata(document))


@bp.route("/api/resource")
@require_oauth()
def resource():
    """Return what the access token gives access to."""
    token = current_token
    data = {"scope": token.scope, "client_id": token.client_id}
    if token.persona is not None:
        data["sub"] = token.persona.sub
    return jsonify(data)


@bp.route("/personas/<int:persona_id>/picture.svg")
def persona_picture(persona_id):
    # The id, not the sub: a sub may hold "/" and could not be a path segment.
    persona = db.get_or_404(Persona, persona_id)
    if not persona.picture_svg:
        abort(404)
    response = Response(persona.picture_svg, mimetype="image/svg+xml")
    # The SVG comes from this origin: it must not run scripts.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'"
    )
    return response


@bp.route("/oauth/jwks")
def jwks():
    response = jsonify(public_jwks())
    # A rotation must show at once.
    response.headers["Cache-Control"] = "no-cache"
    return response
