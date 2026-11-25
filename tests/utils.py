import base64
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.jwk import KeySet

CODE_VERIFIER = generate_token(48)
REDIRECT_URI = "http://client.test/callback"


def basic_auth(client):
    credentials = f"{client['client_id']}:{client['client_secret']}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def bearer(access_token):
    return {"Authorization": f"Bearer {access_token}"}


def authorize_url(**params):
    """Build an authorization URL. Parameters set to None are left out."""
    query = {key: value for key, value in params.items() if value is not None}
    return "/oauth/authorize?" + urlencode(query)


def csrf_token(testapp):
    """Return a valid CSRF token. It works for every form of the session."""
    return testapp.get("/en/server").forms["server"]["csrf_token"].value


def select_persona(testapp, persona):
    """Choose the persona in the persona selector."""
    form = testapp.get("/interaction/persona").forms["select-persona"]
    form["persona"] = str(persona["id"])
    return form.submit()


def consent(testapp, url, *, accept=True):
    """Open the consent page and accept or deny."""
    form = testapp.get(url).forms["consent"]
    return form.submit("accept" if accept else "deny")


def callback_params(res, *, fragment=False):
    """Return the parameters of a redirection to the client."""
    assert res.location.startswith(REDIRECT_URI)
    url = urlparse(res.location)
    query = url.fragment if fragment else url.query
    return {key: values[0] for key, values in parse_qs(query).items()}


def password_token(testapp, client, persona, *, status=200, **params):
    """Request a token with the password grant. Any password is accepted."""
    return testapp.post(
        "/oauth/token",
        {
            "grant_type": "password",
            "username": persona["preferred_username"],
            "password": "anything",
            "scope": "profile",
            **params,
        },
        headers=basic_auth(client),
        status=status,
    )


def client_credentials_token(testapp, client, *, status=200, **params):
    """Request a token with the client credentials grant."""
    return testapp.post(
        "/oauth/token",
        {"grant_type": "client_credentials", **params},
        headers=basic_auth(client),
        status=status,
    )


def oidc_url(client, **params):
    """Build an OpenID Connect authorization URL. None leaves a parameter out."""
    return authorize_url(
        **{
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": "xyz",
            "nonce": generate_token(16),
            "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
            "code_challenge_method": "S256",
            **params,
        }
    )


def exchange_code(testapp, client, code, *, status=200):
    return testapp.post(
        "/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": CODE_VERIFIER,
        },
        headers=basic_auth(client),
        status=status,
    )


def decode_id_token(testapp, id_token):
    """Verify the ID token with the published JWKS. Return the joserfc token."""
    key_set = KeySet.import_key_set(testapp.get("/oauth/jwks").json)
    return jwt.decode(
        id_token, key_set, algorithms=["RS256", "PS256", "ES256", "Ed25519"]
    )
