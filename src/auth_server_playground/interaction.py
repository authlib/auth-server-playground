import time
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from authlib.oauth2 import AuthorizationSession
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oidc.core import AuthorizationSessionMixin
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
from .models import Consent
from .models import Persona
from .models import db

bp = Blueprint("interaction", __name__)

SESSION_PERSONA = "persona_id"
SESSION_AUTH_TIME = "auth_time"


class PlaygroundSession(AuthorizationSession, AuthorizationSessionMixin):
    """The facts that Authlib needs to apply prompt, max_age and the consents.

    AuthorizationSession keeps the start time of the requests in the Flask
    session.
    """

    def get_interaction_time(self, request, interaction):
        if interaction == "login":
            return self.session.get(SESSION_AUTH_TIME)
        if interaction == "consent":
            consent = self.stored_consent(request)
            if consent is not None and consent.covers(request.scope):
                return consent.granted_at
        return None

    def is_consent_needed(self, request):
        consent = self.stored_consent(request)
        return consent is None or not consent.covers(request.scope)

    def stored_consent(self, request):
        return Consent.query.filter_by(
            persona_id=self.user.id, client_id=request.client.client_id
        ).first()


def grant_consent(persona, client_id, scope):
    """Store the consent, merged with the scopes granted before."""
    consent = Consent.query.filter_by(
        persona_id=persona.id, client_id=client_id
    ).first()
    if consent is None:
        consent = Consent(persona_id=persona.id, client_id=client_id, scope="")
        db.session.add(consent)
    scopes = consent.scope.split()
    scopes.extend(item for item in scope_to_list(scope) or [] if item not in scopes)
    consent.scope = " ".join(scopes)
    consent.granted_at = int(time.time())
    db.session.commit()
    return consent


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


def authorization_params(next_url):
    """Return the parameters of the authorization request in next_url, or {}."""
    if not next_url:
        return {}
    url = urlsplit(next_url)
    if url.path != url_for("oauth.authorize"):
        return {}
    return {key: values[0] for key, values in parse_qs(url.query).items()}


def requesting_client(next_url):
    """Return the name of the client of the authorization request in next_url."""
    client_id = authorization_params(next_url).get("client_id")
    if not client_id:
        return None
    client = Client.query.filter_by(client_id=client_id).first()
    if client is None:
        return None
    return client.client_name or client.client_id


def hinted_persona(personas, hint):
    """Return the persona whose sub or email is the login_hint, or None."""
    if not hint:
        return None
    folded = hint.casefold()
    return next(
        (
            p
            for p in personas
            if hint == p.sub or folded == p.claims.get("email", "").casefold()
        ),
        None,
    )


@bp.route("/interaction/persona", methods=["GET", "POST"])
def select_persona():
    form = SelectPersonaForm()
    all_personas = Persona.query.order_by(Persona.id).all()
    form.persona.choices = [
        SelectChoice(persona.id, str(persona)) for persona in all_personas
    ]
    next_url = request.args.get("next")
    if not form.is_submitted():
        hint = authorization_params(next_url).get("login_hint")
        selected = hinted_persona(all_personas, hint) or current_persona()
        form.persona.data = selected.id if selected else None
    if not form.validate_on_submit():
        return render_template(
            "interaction/select_persona.html",
            form=form,
            random_form=ActionForm(prefix="random"),
            personas={persona.id: persona for persona in all_personas},
            client_name=requesting_client(next_url),
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
