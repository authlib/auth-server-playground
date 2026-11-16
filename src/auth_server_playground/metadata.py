"""The metadata that the server publishes, with the URLs of the request."""

from flask import request
from flask import url_for

from .settings import published_metadata
from .store import current_document


def issuer_for(configured):
    """Return the configured issuer, else the URL of the request."""
    return configured or request.url_root.rstrip("/")


def endpoint_urls():
    return {
        "authorization_endpoint": url_for("oauth.authorize", _external=True),
        "token_endpoint": url_for("oauth.issue_token", _external=True),
        "revocation_endpoint": url_for("oauth.revoke_token", _external=True),
        "registration_endpoint": url_for("oauth.register_client", _external=True),
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
