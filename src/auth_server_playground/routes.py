import time

from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from werkzeug.security import gen_salt

from .models import Client
from .models import db

bp = Blueprint("home", __name__)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


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
    return redirect(url_for("admin.index"))
