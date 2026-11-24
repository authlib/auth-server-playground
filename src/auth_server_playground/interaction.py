import time
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from authlib.oauth2 import AuthorizationSession
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oidc.core import AuthorizationSessionMixin
from authlib.oidc.core import get_requested_acr_values
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
from .settings import claims_supported

bp = Blueprint("interaction", __name__)

SESSION_PERSONA = "persona_id"
SESSION_AUTH_TIME = "auth_time"
SESSION_REQUEST_URI = "request_uri"


class PlaygroundSession(AuthorizationSession, AuthorizationSessionMixin):
    """The facts that Authlib needs to apply prompt, max_age and the consents.

    AuthorizationSession keeps the start time of the requests in the Flask
    session.
    """

    def get_interaction_time(self, request, interaction):
        if interaction == "login":
            return self.session.get(SESSION_AUTH_TIME)

        if interaction != "consent":
            return None

        consent = self.covering_consent(request)
        return consent.granted_at if consent else None

    def get_acr(self, request):
        """Return the first requested acr value. The playground meets any value."""
        values = get_requested_acr_values(request)
        return values[0] if values else None

    def is_account_selection_needed(self, request):
        """Tell if the login_hint is about another persona."""
        hint = request.payload.data.get("login_hint")
        if not hint:
            return False

        hinted = hinted_persona(Persona.query.all(), hint)
        return hinted is not None and hinted.id != self.user.id

    def is_consent_needed(self, request):
        return self.covering_consent(request) is None

    def covering_consent(self, request):
        """Return the stored consent when it covers the scope, else None."""
        consent = stored_consent(self.user.id, request.client.client_id)
        if consent is None or not consent.covers(request.scope):
            return None

        return consent


def stored_consent(persona_id, client_id):
    """Return the consent of the persona for the client, or None."""
    return Consent.query.filter_by(persona_id=persona_id, client_id=client_id).first()


def grant_consent(persona, client_id, scope):
    """Store the consent, merged with the scopes granted before."""
    consent = stored_consent(persona.id, client_id)
    if consent is None:
        consent = Consent(persona_id=persona.id, client_id=client_id, scope="")
        db.session.add(consent)

    scopes = consent.scope.split()
    scopes.extend(item for item in scope_to_list(scope) or [] if item not in scopes)
    consent.scope = " ".join(scopes)
    consent.granted_at = int(time.time())
    db.session.commit()
    return consent


def extra_claims(claims_request, scope):
    """Return the claims that the claims parameter asks for beyond the scope."""
    if not claims_request:
        return []

    given = claims_supported(scope_to_list(scope) or [])
    requested = [
        claim
        for member in ("userinfo", "id_token")
        for claim in claims_request.get(member) or {}
    ]
    return [claim for claim in dict.fromkeys(requested) if claim not in given]


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
    """Return the client of the authorization request in next_url, or None."""
    client_id = authorization_params(next_url).get("client_id")
    if not client_id:
        return None

    return Client.query.filter_by(client_id=client_id).first()


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
        hint = request.args.get("login_hint")
        selected = hinted_persona(all_personas, hint) or current_persona()
        form.persona.data = selected.id if selected else None

    if not form.validate_on_submit():
        return render_template(
            "interaction/select_persona.html",
            form=form,
            random_form=ActionForm(prefix="random"),
            personas={persona.id: persona for persona in all_personas},
            client=requesting_client(next_url),
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
