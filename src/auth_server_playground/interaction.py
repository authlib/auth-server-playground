import time
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from flask import Blueprint
from flask import abort
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_babel import get_locale
from wtforms.fields import SelectChoice

from . import personas
from .forms import ActionForm
from .forms import SelectPersonaForm
from .models import Client
from .models import Persona
from .models import db

bp = Blueprint("interaction", __name__)

SESSION_PERSONA = "persona_id"
SESSION_AUTH_TIME = "auth_time"


def current_persona():
    """Return the persona of the session, or None."""
    persona_id = session.get(SESSION_PERSONA)
    if persona_id is None:
        return None
    persona = db.session.get(Persona, persona_id)
    if persona is None:
        forget_persona()
    return persona


def forget_persona():
    session.pop(SESSION_PERSONA, None)
    session.pop(SESSION_AUTH_TIME, None)


def is_local_path(url):
    """Tell whether the URL is a path on this server, and not another site."""
    if not url.isprintable() or "\\" in url:
        return False
    return url.startswith("/") and not url.startswith("//")


def after_interaction():
    next_url = request.args.get("next")
    if next_url and is_local_path(next_url):
        return redirect(next_url)
    return redirect(url_for("admin.index"))


def requesting_client(next_url):
    """Return the name of the client of the authorization request in next_url."""
    if not next_url:
        return None
    url = urlsplit(next_url)
    if url.path != url_for("oauth.authorize"):
        return None
    client_id = parse_qs(url.query).get("client_id", [None])[0]
    if not client_id:
        return None
    client = Client.query.filter_by(client_id=client_id).first()
    if client is None:
        return None
    return client.client_name or client.client_id


@bp.route("/interaction/persona", methods=["GET", "POST"])
def select_persona():
    form = SelectPersonaForm()
    all_personas = Persona.query.order_by(Persona.id).all()
    form.persona.choices = [
        SelectChoice(persona.id, str(persona)) for persona in all_personas
    ]
    if not form.validate_on_submit():
        return render_template(
            "interaction/select_persona.html",
            form=form,
            random_form=ActionForm(prefix="random"),
            personas={persona.id: persona for persona in all_personas},
            client_name=requesting_client(request.args.get("next")),
        )

    act_as(form.persona.data)
    return after_interaction()


def act_as(persona_id):
    session[SESSION_PERSONA] = persona_id
    session[SESSION_AUTH_TIME] = int(time.time())


@bp.route("/interaction/persona/random", methods=["POST"])
def random_persona():
    if not ActionForm(prefix="random").validate_on_submit():
        abort(400)

    locale = personas.random_locale_for(get_locale().language)
    act_as(personas.create_random_persona(locale).id)
    return after_interaction()


@bp.route("/interaction/forget")
def forget():
    forget_persona()
    return redirect(url_for("admin.index"))
