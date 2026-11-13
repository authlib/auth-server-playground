import base64
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

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
