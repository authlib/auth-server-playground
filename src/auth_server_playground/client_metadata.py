"""The client metadata rules that Authlib does not apply."""

from urllib.parse import urlsplit

from authlib.common.security import is_secure_transport


def is_web_url(url, schemes=("http", "https")):
    try:
        parts = urlsplit(url)
    except ValueError:
        return False

    return parts.scheme in schemes and bool(parts.hostname)


def client_metadata_errors(metadata):
    """Return the errors of the client metadata, by metadata key.

    These rules need no network request.
    """
    errors = {}
    # The server fetches these URLs, so a loopback address gets no exception.
    if not all(
        is_web_url(uri) and is_secure_transport(uri, allow_loopback=False)
        for uri in metadata.get("request_uris", [])
    ):
        errors["request_uris"] = "request_uris holds https URLs only."

    return errors
