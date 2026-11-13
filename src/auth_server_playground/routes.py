import time

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
from werkzeug.security import gen_salt

from .forms import ConsentForm
from .interaction import current_persona
from .models import Client
from .models import db
from .oauth2 import authorization
from .oauth2 import require_oauth

bp = Blueprint("home", __name__)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route("/")
def home():
    clients = Client.query.order_by(Client.id).all()
    return render_template("home.html", persona=current_persona(), clients=clients)


@bp.route("/create_client", methods=("GET", "POST"))
def create_client():
    if request.method == "GET":
        return render_template("create_client.html")

    client = Client(
        client_id=gen_salt(24),
        client_id_issued_at=int(time.time()),
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"],
    }
    client.set_client_metadata(client_metadata)

    if form["token_endpoint_auth_method"] == "none":
        client.client_secret = ""
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect(url_for("home.home"))


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

    try:
        grant = authorization.get_consent_grant(end_user=persona)
    except OAuth2Error as error:
        return authorization.handle_error_response(request, error)

    form = ConsentForm(persona_id=persona.id)
    if request.method == "POST":
        if not form.validate():
            abort(400)
        if form.persona_id.data == persona.id:
            grant_user = persona if form.accept.data else None
            return authorization.create_authorization_response(
                grant=grant, grant_user=grant_user
            )
        flash(_("The persona changed since this page was shown."), "warning")
        form.persona_id.data = persona.id
    return render_template(
        "interaction/consent.html", form=form, grant=grant, persona=persona
    )


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


@bp.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    return authorization.create_endpoint_response("revocation")


@bp.route("/api/me")
@require_oauth("profile")
def api_me():
    persona = current_token.persona
    if persona is None:
        return jsonify({})
    claims = {"sub": persona.sub, "preferred_username": persona.preferred_username}
    return jsonify({key: value for key, value in claims.items() if value})
