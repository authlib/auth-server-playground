import itertools
import socket

import httpcore2
import httpx2
import pytest

from auth_server_playground import outbound
from auth_server_playground.outbound import OutboundError
from auth_server_playground.outbound import PublicAddressBackend
from auth_server_playground.outbound import fetch

URL = "https://client.test/jwks.json"


def test_fetch_returns_the_body(outbound_urls):
    outbound_urls.responses[URL] = httpx2.Response(200, content=b'{"keys": []}')
    assert fetch(URL) == b'{"keys": []}'


def test_fetch_headers(monkeypatch):
    seen = []

    def handle(request):
        seen.append(request.headers)
        return httpx2.Response(200, stream=httpx2.ByteStream(b""))

    monkeypatch.setattr(
        outbound, "make_transport", lambda allow: httpx2.MockTransport(handle)
    )
    fetch(URL)
    assert seen[0]["User-Agent"] == "auth-server-playground"
    assert seen[0]["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "url",
    ["ftp://client.test/jwks.json", "file:///etc/passwd", "not a url", "http://[::1"],
)
def test_fetch_refuses_other_schemes(outbound_urls, url):
    with pytest.raises(OutboundError, match="http and https"):
        fetch(url)
    assert outbound_urls.requested == []


def test_fetch_refuses_redirects(outbound_urls):
    outbound_urls.responses[URL] = httpx2.Response(
        302, headers={"Location": "http://10.0.0.1/"}
    )
    with pytest.raises(OutboundError, match="redirect"):
        fetch(URL)
    assert outbound_urls.requested == [URL]


def test_fetch_refuses_error_statuses(outbound_urls):
    with pytest.raises(OutboundError, match="HTTP status 404"):
        fetch(URL)


def test_fetch_accepts_64_kib(outbound_urls):
    outbound_urls.responses[URL] = httpx2.Response(200, content=b"a" * 65536)
    assert len(fetch(URL)) == 65536


def test_fetch_refuses_larger_bodies(outbound_urls):
    outbound_urls.responses[URL] = httpx2.Response(200, content=b"a" * 65537)
    with pytest.raises(OutboundError, match="64 KiB"):
        fetch(URL)


def test_fetch_stops_at_the_deadline(outbound_urls, monkeypatch):
    outbound_urls.responses[URL] = httpx2.Response(
        200, content=iter([b"a", b"b", b"c"])
    )
    clock = itertools.chain([0.0, 5.0], itertools.repeat(10.5))
    monkeypatch.setattr(outbound.time, "monotonic", lambda: next(clock))
    with pytest.raises(OutboundError, match="10 seconds"):
        fetch(URL)


def test_fetch_wraps_transport_errors(monkeypatch):
    def handle(request):
        raise httpx2.ConnectError("connection refused")

    monkeypatch.setattr(
        outbound, "make_transport", lambda allow: httpx2.MockTransport(handle)
    )
    with pytest.raises(OutboundError, match="connection refused"):
        fetch(URL)


def addresses(*values):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, 443)) for value in values
    ]


@pytest.fixture
def connections(monkeypatch):
    """Record the hosts that the backend connects to, without connecting."""
    hosts = []

    def connect_tcp(self, host, port, *args, **kwargs):
        hosts.append(host)
        return "stream"

    monkeypatch.setattr(httpcore2.SyncBackend, "connect_tcp", connect_tcp)
    return hosts


def resolve_to(monkeypatch, *values):
    monkeypatch.setattr(
        outbound.socket, "getaddrinfo", lambda *args, **kwargs: addresses(*values)
    )


def test_backend_connects_to_the_checked_address(monkeypatch, connections):
    resolve_to(monkeypatch, "93.184.215.14")
    stream = PublicAddressBackend().connect_tcp("client.test", 443)
    assert stream == "stream"
    assert connections == ["93.184.215.14"]


@pytest.mark.parametrize(
    "values",
    [
        ("10.0.0.3",),
        ("127.0.0.1",),
        ("169.254.169.254",),
        ("100.64.0.1",),
        ("::1",),
        ("fe80::1",),
        ("93.184.215.14", "192.168.1.1"),
    ],
)
def test_backend_refuses_non_global_addresses(monkeypatch, connections, values):
    resolve_to(monkeypatch, *values)
    with pytest.raises(OutboundError, match="is not public"):
        PublicAddressBackend().connect_tcp("client.test", 443)
    assert connections == []


def test_backend_reports_resolution_errors(monkeypatch, connections):
    def fail(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(outbound.socket, "getaddrinfo", fail)
    with pytest.raises(httpcore2.ConnectError, match="not known"):
        PublicAddressBackend().connect_tcp("client.test", 443)


def test_private_addresses_refused_end_to_end():
    # 127.0.0.1 resolves without network, and the check stops before connecting.
    with pytest.raises(OutboundError, match="127.0.0.1 is not public"):
        fetch("http://127.0.0.1:9/", allow_private_addresses=False)


def test_private_addresses_allowed_end_to_end():
    # Nothing listens on port 9 (discard). The error comes from the connection.
    with pytest.raises(OutboundError) as error:
        fetch("http://127.0.0.1:9/", allow_private_addresses=True)
    assert "not public" not in str(error.value)
