import httpx2
import pytest
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from auth_server_playground.personas import MINIMAL_SUB
from tests.conftest import make_client
from tests.utils import CODE_VERIFIER
from tests.utils import REDIRECT_URI
from tests.utils import authorize_url
from tests.utils import bearer
from tests.utils import callback_params
from tests.utils import consent
from tests.utils import decode_id_token
from tests.utils import exchange_code

# joserfc warns on each use of alg none.
pytestmark = pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")


def request_claims(client, **params):
    """Return the claims of a request object for the code flow."""
    return {
        "client_id": client["client_id"],
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": "from-the-object",
        "nonce": generate_token(16),
        "code_challenge": create_s256_code_challenge(CODE_VERIFIER),
        "code_challenge_method": "S256",
        **params,
    }


def error_of(res):
    """Return the error code, from a redirection to the client or a JSON body."""
    if res.status_int == 303:
        return callback_params(res)["error"]

    return res.json["error"]


def unsigned(claims):
    return jwt.encode({"alg": "none"}, claims, None, algorithms=["none"])


def test_unsigned_request_object(logged_in, client):
    claims = request_claims(client)
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    params = callback_params(consent(logged_in, url))
    assert params["state"] == "from-the-object"
    id_token = exchange_code(logged_in, client, params["code"]).json["id_token"]
    assert decode_id_token(logged_in, id_token).claims["nonce"] == claims["nonce"]


def test_unsigned_request_object_sent_with_post(logged_in, client):
    res = logged_in.post(
        "/oauth/authorize",
        {"client_id": client["client_id"], "request": unsigned(request_claims(client))},
        status=303,
    )
    params = callback_params(res.follow().forms["consent"].submit("accept"))
    assert params["state"] == "from-the-object"
    assert "code" in params


def test_request_uri_is_refused_by_default(logged_in, client):
    url = authorize_url(
        client_id=client["client_id"], request_uri="https://client.test/request.jwt"
    )
    res = logged_in.get(url, status=400)
    assert res.json["error"] == "request_uri_not_supported"


REQUEST_URI = "https://client.test/request.jwt"


@pytest.fixture
def request_uri_client(app, configure):
    configure(metadata={"request_uri_parameter_supported": True})
    return make_client(
        app,
        client_id="request-uri-client",
        client_secret="request-uri-secret",
        metadata={
            "scope": "openid profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "request_uris": [REQUEST_URI],
        },
    )


def serve(outbound_urls, claims, url=REQUEST_URI):
    outbound_urls.responses[url] = httpx2.Response(
        200, content=unsigned(claims).encode()
    )


def request_uri_url(client, request_uri=REQUEST_URI):
    return authorize_url(client_id=client["client_id"], request_uri=request_uri)


def test_request_uri(logged_in, request_uri_client, outbound_urls):
    serve(outbound_urls, request_claims(request_uri_client))
    params = callback_params(consent(logged_in, request_uri_url(request_uri_client)))
    assert params["state"] == "from-the-object"
    assert outbound_urls.requested == [REQUEST_URI, REQUEST_URI]


def test_request_uri_with_a_stored_consent(
    logged_in, request_uri_client, outbound_urls
):
    serve(outbound_urls, request_claims(request_uri_client))
    consent(logged_in, request_uri_url(request_uri_client))
    outbound_urls.requested.clear()
    # Authlib refuses a nonce that it has seen, for any authorization request.
    serve(outbound_urls, request_claims(request_uri_client))
    res = logged_in.get(request_uri_url(request_uri_client))
    assert "code" in callback_params(res)
    assert outbound_urls.requested == [REQUEST_URI]


def test_request_uri_document_changed(logged_in, request_uri_client, outbound_urls):
    serve(outbound_urls, request_claims(request_uri_client))
    form = logged_in.get(request_uri_url(request_uri_client)).forms["consent"]
    serve(outbound_urls, request_claims(request_uri_client, nonce="another-nonce"))
    params = callback_params(form.submit("accept"))
    assert params["error"] == "invalid_request_uri"
    assert params["state"] == "from-the-object"


def session_of(app, testapp):
    serializer = app.session_interface.get_signing_serializer(app)
    return serializer.loads(testapp.cookies[app.config["SESSION_COOKIE_NAME"]])


def test_request_uri_denied(app, logged_in, request_uri_client, outbound_urls):
    serve(outbound_urls, request_claims(request_uri_client))
    form = logged_in.get(request_uri_url(request_uri_client)).forms["consent"]
    assert session_of(app, logged_in)["request_uri"]
    params = callback_params(form.submit("deny"))
    assert params["error"] == "access_denied"
    assert not session_of(app, logged_in).get("request_uri")


def test_two_consent_pages(logged_in, request_uri_client, outbound_urls, configure):
    configure(metadata={"require_request_uri_registration": False})
    other = "https://client.test/other.jwt"
    serve(outbound_urls, request_claims(request_uri_client))
    serve(outbound_urls, request_claims(request_uri_client), other)
    first = logged_in.get(request_uri_url(request_uri_client)).forms["consent"]
    logged_in.get(request_uri_url(request_uri_client, other))
    # A consent page without request_uri does not clear the others.
    plain = authorize_url(
        client_id=request_uri_client["client_id"],
        response_type="code",
        redirect_uri=REDIRECT_URI,
        scope="openid profile",
        state="plain",
        code_challenge=create_s256_code_challenge(CODE_VERIFIER),
        code_challenge_method="S256",
    )
    assert logged_in.get(plain).forms["consent"]
    assert "code" in callback_params(first.submit("accept"))


def test_request_uri_document_changed_with_the_implicit_grant(
    logged_in, app, outbound_urls, configure, legacy_grants
):
    configure(metadata={"request_uri_parameter_supported": True})
    client = make_client(
        app,
        client_id="implicit-request-uri-client",
        client_secret="",
        metadata={
            "scope": "openid profile",
            "grant_types": ["implicit"],
            "response_types": ["token"],
            "token_endpoint_auth_method": "none",
            "request_uris": [REQUEST_URI],
        },
    )
    claims = request_claims(client, response_type="token")
    for key in ("code_challenge", "code_challenge_method", "nonce"):
        del claims[key]

    serve(outbound_urls, claims)
    form = logged_in.get(request_uri_url(client)).forms["consent"]
    serve(outbound_urls, {**claims, "scope": "profile"})
    # The implicit grant answers in the fragment.
    params = callback_params(form.submit("accept"), fragment=True)
    assert params["error"] == "invalid_request_uri"
    assert params["state"] == "from-the-object"


def test_unregistered_request_uri(logged_in, request_uri_client, outbound_urls):
    url = request_uri_url(request_uri_client, "https://client.test/other.jwt")
    res = logged_in.get(url, status=400)
    assert res.json["error"] == "invalid_request_uri"
    assert outbound_urls.requested == []


def test_unregistered_request_uri_without_registration(
    logged_in, request_uri_client, outbound_urls, configure
):
    configure(metadata={"require_request_uri_registration": False})
    other = "https://client.test/other.jwt"
    serve(outbound_urls, request_claims(request_uri_client), other)
    res = consent(logged_in, request_uri_url(request_uri_client, other))
    assert "code" in callback_params(res)


@pytest.mark.parametrize("insecure_transport", [False])
def test_request_uri_over_http_without_insecure_transport(
    logged_in, request_uri_client, outbound_urls, configure
):
    configure(metadata={"require_request_uri_registration": False})
    other = "http://client.test/request.jwt"
    serve(outbound_urls, request_claims(request_uri_client), other)
    res = logged_in.get(request_uri_url(request_uri_client, other), status=400)
    assert res.json["error"] == "invalid_request_uri"
    assert outbound_urls.requested == []


def test_request_uri_over_http_with_insecure_transport(
    logged_in, request_uri_client, outbound_urls, configure
):
    configure(metadata={"require_request_uri_registration": False})
    other = "http://client.test/request.jwt"
    serve(outbound_urls, request_claims(request_uri_client), other)
    res = consent(logged_in, request_uri_url(request_uri_client, other))
    assert "code" in callback_params(res)


@pytest.mark.parametrize("insecure_transport", [False])
def test_request_uri_to_loopback_over_http(
    logged_in, request_uri_client, outbound_urls, configure
):
    configure(metadata={"require_request_uri_registration": False})
    other = "http://localhost/request.jwt"
    serve(outbound_urls, request_claims(request_uri_client), other)
    res = logged_in.get(request_uri_url(request_uri_client, other), status=400)
    assert res.json["error"] == "invalid_request_uri"
    assert outbound_urls.requested == []


def test_request_uri_without_host(
    logged_in, request_uri_client, outbound_urls, configure
):
    configure(metadata={"require_request_uri_registration": False})
    url = request_uri_url(request_uri_client, "https:///request.jwt")
    res = logged_in.get(url, status=400)
    assert res.json["error"] == "invalid_request_uri"
    assert outbound_urls.requested == []


def test_request_uri_fetch_error(logged_in, request_uri_client, outbound_urls):
    res = logged_in.get(request_uri_url(request_uri_client), status=400)
    assert res.json["error"] == "invalid_request_uri"


def test_request_uri_that_is_not_text(logged_in, request_uri_client, outbound_urls):
    outbound_urls.responses[REQUEST_URI] = httpx2.Response(200, content=b"\xff\xfe")
    res = logged_in.get(request_uri_url(request_uri_client), status=400)
    assert res.json["error"] == "invalid_request_uri"


def test_claims_member_of_the_request_object(logged_in, client):
    claims = request_claims(client, claims={"userinfo": {"email": None}})
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    code = callback_params(consent(logged_in, url))["code"]
    access_token = exchange_code(logged_in, client, code).json["access_token"]
    res = logged_in.get("/oauth/userinfo", headers=bearer(access_token))
    assert res.json["email"] == "alice@example.com"


def test_login_hint_of_the_request_object(testapp, client, other_persona):
    claims = request_claims(client, login_hint=MINIMAL_SUB)
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    res = testapp.get(url).follow()
    assert res.forms["select-persona"]["persona"].value == str(other_persona["id"])


def test_ui_locales_of_the_request_object_on_the_consent_page(logged_in, client):
    claims = request_claims(client, ui_locales="fr")
    url = authorize_url(client_id=client["client_id"], request=unsigned(claims))
    res = logged_in.get(url)
    assert '<html lang="fr"' in res.text


def test_consent_shows_the_parameters_of_the_request_object(logged_in, client):
    request = unsigned(request_claims(client, claims={"userinfo": {"email": None}}))
    url = authorize_url(client_id=client["client_id"], request=request)
    details = logged_in.get(url).html.select_one("details").get_text(" ", strip=True)
    assert "from-the-object" in details
    assert '{"userinfo": {"email": null}}' in details
    assert request not in details


def fr_request_url(client):
    claims = request_claims(client, ui_locales="fr")
    return authorize_url(client_id=client["client_id"], request=unsigned(claims))


def test_ui_locales_of_the_request_object_on_the_persona_page(testapp, client):
    res = testapp.get(fr_request_url(client)).follow()
    assert '<html lang="fr"' in res.text
    assert "ui_locales=fr" in res.forms["random"].action


def test_change_persona_keeps_the_ui_locales_of_the_request_object(logged_in, client):
    page = logged_in.get(fr_request_url(client))
    link = page.html.select_one("a[href^='/interaction/persona']")["href"]
    assert '<html lang="fr"' in logged_in.get(link).text


def test_unsigned_request_object_refused_without_none(logged_in, client, configure):
    configure(metadata={"request_object_signing_alg_values_supported": ["RS256"]})
    url = authorize_url(
        client_id=client["client_id"], request=unsigned(request_claims(client))
    )
    assert logged_in.get(url, status=400).json["error"] == "invalid_request"


def test_unsigned_request_object_refused_when_signature_required(
    logged_in, client, configure
):
    configure(metadata={"require_signed_request_object": True})
    url = authorize_url(
        client_id=client["client_id"], request=unsigned(request_claims(client))
    )
    assert logged_in.get(url, status=400).json["error"] == "invalid_request"


SECRET = "a-client-secret-of-forty-eight-characters-123456"
JWKS_URI = "https://client.test/jwks.json"


def keyed_client(
    app, rsa_pool, client_id="keyed-client", client_secret=SECRET, **metadata
):
    key = RSAKey.import_key(rsa_pool[0])
    return make_client(
        app,
        client_id=client_id,
        client_secret=client_secret,
        metadata={
            "scope": "openid profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks": {"keys": [key.as_dict(private=False)]},
            **metadata,
        },
    )


def signed(claims, key, alg):
    return jwt.encode({"alg": alg}, claims, key, algorithms=[alg])


def request_url(client, request):
    return authorize_url(client_id=client["client_id"], request=request)


@pytest.mark.parametrize("alg", ["RS256", "PS256"])
def test_request_object_signed_with_the_client_key(app, logged_in, rsa_pool, alg):
    client = keyed_client(app, rsa_pool)
    request = signed(request_claims(client), RSAKey.import_key(rsa_pool[0]), alg)
    params = callback_params(consent(logged_in, request_url(client, request)))
    assert params["state"] == "from-the-object"


def test_request_object_signed_with_the_client_secret(app, logged_in, rsa_pool):
    client = keyed_client(app, rsa_pool)
    request = signed(request_claims(client), OctKey.import_key(SECRET), "HS256")
    params = callback_params(consent(logged_in, request_url(client, request)))
    assert params["state"] == "from-the-object"


def test_request_object_signed_with_another_key(app, logged_in, rsa_pool):
    client = keyed_client(app, rsa_pool)
    request = signed(request_claims(client), RSAKey.import_key(rsa_pool[1]), "RS256")
    res = logged_in.get(request_url(client, request), status="*")
    assert error_of(res) == "invalid_request_object"


def test_server_requires_signed_objects(app, logged_in, rsa_pool, configure):
    configure(metadata={"require_signed_request_object": True})
    client = keyed_client(app, rsa_pool)
    res = logged_in.get(
        request_url(client, unsigned(request_claims(client))), status="*"
    )
    assert error_of(res) == "invalid_request"
    request = signed(request_claims(client), RSAKey.import_key(rsa_pool[0]), "RS256")
    assert "code" in callback_params(consent(logged_in, request_url(client, request)))


def test_client_requires_signed_objects(app, logged_in, rsa_pool):
    client = keyed_client(app, rsa_pool, require_signed_request_object=True)
    res = logged_in.get(
        request_url(client, unsigned(request_claims(client))), status="*"
    )
    assert error_of(res) == "invalid_request"


def test_client_algorithm(app, logged_in, rsa_pool):
    client = keyed_client(app, rsa_pool, request_object_signing_alg="PS256")
    key = RSAKey.import_key(rsa_pool[0])
    res = logged_in.get(
        request_url(client, signed(request_claims(client), key, "RS256")), status="*"
    )
    assert error_of(res) == "invalid_request"
    request = signed(request_claims(client), key, "PS256")
    assert "code" in callback_params(consent(logged_in, request_url(client, request)))


def test_client_algorithm_unsupported_by_the_server(
    app, logged_in, rsa_pool, configure
):
    configure(
        metadata={"request_object_signing_alg_values_supported": ["none", "RS256"]}
    )
    client = keyed_client(app, rsa_pool, request_object_signing_alg="PS256")
    request = signed(request_claims(client), RSAKey.import_key(rsa_pool[0]), "PS256")
    assert error_of(logged_in.get(request_url(client, request), status="*")) == (
        "invalid_request"
    )


def test_server_algorithms(app, logged_in, rsa_pool, configure):
    configure(
        metadata={"request_object_signing_alg_values_supported": ["none", "RS256"]}
    )
    client = keyed_client(app, rsa_pool)
    request = signed(request_claims(client), OctKey.import_key(SECRET), "HS256")
    assert error_of(logged_in.get(request_url(client, request), status="*")) == (
        "invalid_request"
    )


def test_unsigned_object_fetches_nothing(app, logged_in, rsa_pool, outbound_urls):
    client = keyed_client(app, rsa_pool, jwks=None, jwks_uri=JWKS_URI)
    params = callback_params(
        consent(logged_in, request_url(client, unsigned(request_claims(client))))
    )
    assert "code" in params
    assert outbound_urls.requested == []


def test_keys_from_jwks_uri(app, logged_in, rsa_pool, outbound_urls):
    key = RSAKey.import_key(rsa_pool[0])
    outbound_urls.responses[JWKS_URI] = httpx2.Response(
        200, json={"keys": [key.as_dict(private=False)]}
    )
    client = keyed_client(app, rsa_pool, jwks=None, jwks_uri=JWKS_URI)
    request = signed(request_claims(client), key, "RS256")
    assert "code" in callback_params(consent(logged_in, request_url(client, request)))


def test_jwks_uri_error(app, logged_in, rsa_pool, outbound_urls):
    client = keyed_client(app, rsa_pool, jwks=None, jwks_uri=JWKS_URI)
    request = signed(request_claims(client), RSAKey.import_key(rsa_pool[0]), "RS256")
    res = logged_in.get(request_url(client, request), status="*")
    assert error_of(res) == "invalid_request_object"


def test_error_of_the_object_is_redirected_to_the_client(logged_in, client):
    claims = request_claims(client, scope="openid unknown-scope")
    res = logged_in.get(request_url(client, unsigned(claims)), status="*")
    assert res.status_int == 303
    assert error_of(res) == "invalid_scope"


def test_request_object_signed_with_hmac_by_a_client_without_secret(
    app, logged_in, rsa_pool
):
    client = keyed_client(
        app, rsa_pool, client_secret=None, token_endpoint_auth_method="none"
    )
    request = signed(request_claims(client), OctKey.import_key(SECRET), "HS256")
    res = logged_in.get(request_url(client, request), status="*")
    assert error_of(res) == "invalid_request_object"


def test_request_parameter_disabled(logged_in, client, configure):
    configure(metadata={"request_parameter_supported": False})
    url = authorize_url(
        client_id=client["client_id"], request=unsigned(request_claims(client))
    )
    assert error_of(logged_in.get(url, status=400)) == "request_not_supported"
