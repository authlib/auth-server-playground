import time

from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for

from .forms import SelectPersonaForm
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
    return redirect(url_for("home.home"))


@bp.route("/interaction/persona", methods=["GET", "POST"])
def select_persona():
    form = SelectPersonaForm()
    form.persona.choices = [
        (persona.id, str(persona)) for persona in Persona.query.order_by(Persona.id)
    ]
    if not form.validate_on_submit():
        return render_template("interaction/select_persona.html", form=form)

    session[SESSION_PERSONA] = form.persona.data
    session[SESSION_AUTH_TIME] = int(time.time())
    return after_interaction()


@bp.route("/interaction/forget")
def forget():
    forget_persona()
    return redirect(url_for("home.home"))
