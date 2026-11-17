"""Requests from the server to the URLs that clients give, such as jwks_uri."""

import ipaddress
import socket
import time
from urllib.parse import urlsplit

import httpcore2
import httpx2

#: Seconds for each network operation.
TIMEOUT = 5.0
#: Seconds for the whole response.
DEADLINE = 10.0
MAX_SIZE = 64 * 1024
HEADERS = {
    "User-Agent": "auth-server-playground",
    # A compressed body could expand far beyond MAX_SIZE in memory.
    "Accept-Encoding": "identity",
}


class OutboundError(Exception):
    """A request to a client URL failed. The message gives the reason."""


class PublicAddressBackend(httpcore2.SyncBackend):
    """Connect only to global addresses.

    The backend connects to the address it checked, not to the host name.
    So a DNS answer that changes between the check and the connection has
    no effect. TLS still uses the host name, which httpcore passes apart.
    """

    def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise httpcore2.ConnectError(str(error)) from error

        found = [info[4][0] for info in infos]
        for address in found:
            if not ipaddress.ip_address(address).is_global:
                raise OutboundError(f"address {address} is not public")

        return super().connect_tcp(
            found[0], port, timeout, local_address, socket_options
        )


class PublicAddressTransport(httpx2.HTTPTransport):
    """An HTTP transport whose connections go through PublicAddressBackend."""

    def __init__(self):
        super().__init__()
        # httpx2 has no option for the network backend of its pool.
        self._pool = httpcore2.ConnectionPool(
            ssl_context=httpx2.create_ssl_context(),
            network_backend=PublicAddressBackend(),
        )


def make_transport(allow_private_addresses):
    if allow_private_addresses:
        return httpx2.HTTPTransport()

    return PublicAddressTransport()


def fetch(url, *, allow_private_addresses=True):
    """Return the body of a GET request to the URL."""
    try:
        scheme = urlsplit(url).scheme
    except ValueError:
        scheme = None

    if scheme not in ("http", "https"):
        raise OutboundError("only http and https URLs are fetched")

    deadline = time.monotonic() + DEADLINE
    body = bytearray()
    try:
        with (
            httpx2.Client(
                transport=make_transport(allow_private_addresses),
                timeout=TIMEOUT,
                headers=HEADERS,
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.is_redirect:
                raise OutboundError(f"redirect refused (HTTP {response.status_code})")

            if not response.is_success:
                raise OutboundError(f"HTTP status {response.status_code}")

            for chunk in response.iter_raw():
                body.extend(chunk)
                if len(body) > MAX_SIZE:
                    raise OutboundError("response larger than 64 KiB")

                if time.monotonic() > deadline:
                    raise OutboundError("no full response in 10 seconds")
    except (httpx2.HTTPError, httpx2.InvalidURL) as error:
        raise OutboundError(str(error) or type(error).__name__) from error

    return bytes(body)
