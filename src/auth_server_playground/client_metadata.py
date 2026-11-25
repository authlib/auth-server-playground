"""The client metadata rules that Authlib does not apply."""

import json
from urllib.parse import urlsplit

from authlib.common.security import is_secure_transport

from .outbound import OutboundError
from .outbound import fetch


def is_web_url(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return False

    return parts.scheme in ("http", "https") and bool(parts.hostname)


def is_fetchable_url(url):
    """Tell if the server may fetch the URL.

    It must be https, with no loopback exception. AUTHLIB_INSECURE_TRANSPORT
    also allows http.
    """
    return is_web_url(url) and is_secure_transport(url, allow_loopback=False)


def client_metadata_errors(metadata):
    """Return the errors of the client metadata, by metadata key.

    These rules need no network request.
    """
    errors = {}
    # The server fetches these URLs, so a loopback address gets no exception.
    if not all(is_fetchable_url(uri) for uri in metadata.get("request_uris") or []):
        errors["request_uris"] = "request_uris holds https URLs only."

    sector_uri = metadata.get("sector_identifier_uri")
    if sector_uri and not is_fetchable_url(sector_uri):
        errors["sector_identifier_uri"] = "sector_identifier_uri holds an https URL."

    # Per OIDC Core §8.1, the redirect URIs then give the sector.
    if metadata.get("subject_type") == "pairwise" and not sector_uri:
        hosts = {urlsplit(uri).hostname for uri in metadata.get("redirect_uris") or []}
        if len(hosts) > 1:
            errors["redirect_uris"] = (
                "A pairwise client without sector_identifier_uri has its redirect "
                "URIs on one host."
            )

    return errors


def sector_errors(metadata, *, allow_private_addresses, previous=None):
    """Fetch sector_identifier_uri, and check that it lists every redirect URI.

    Per OIDC Registration §5. With the stored metadata of the client as
    `previous`, it fetches nothing when the URL and the redirect URIs did not
    change. So a down sector host does not block the other changes.
    """
    uri = metadata.get("sector_identifier_uri")
    if not uri:
        return {}

    if previous is not None and all(
        previous.get(key) == metadata.get(key)
        for key in ("sector_identifier_uri", "redirect_uris")
    ):
        return {}

    try:
        listed = json.loads(fetch(uri, allow_private_addresses=allow_private_addresses))
    except OutboundError as error:
        return {"sector_identifier_uri": str(error)}
    except ValueError:
        return {"sector_identifier_uri": "the response is not JSON"}

    if not isinstance(listed, list) or not all(
        isinstance(item, str) for item in listed
    ):
        return {"sector_identifier_uri": "the response is not a JSON array of strings"}

    if missing := [
        item for item in metadata.get("redirect_uris") or [] if item not in listed
    ]:
        return {
            "sector_identifier_uri": (
                f"the document does not list {', '.join(missing)}"
            )
        }

    return {}
