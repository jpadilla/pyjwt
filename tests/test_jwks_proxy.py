import json
import ssl
import threading
import urllib.request
from contextlib import contextmanager
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest import mock

import pytest

from jwt import PyJWKClient
from jwt.jwks_client import _NoRedirectHandler


@contextmanager
def local_endpoint() -> Iterator[tuple[str, list[tuple[str, str | None]]]]:
    requests: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append((self.path, self.headers.get("X-Test")))
            body = json.dumps({"keys": []}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("explicit", [False, True])
def test_fetch_data_through_proxy(explicit: bool) -> None:
    with local_endpoint() as (proxy_url, requests):
        proxies = {"http": proxy_url}
        with (
            mock.patch("urllib.request.getproxies", return_value=proxies),
            mock.patch("urllib.request.proxy_bypass", return_value=False),
        ):
            options: dict[str, Any] = {"proxies": proxies} if explicit else {}
            client = PyJWKClient(
                "http://jwks.invalid/keys",
                cache_jwk_set=False,
                headers={"X-Test": "forwarded"},
                timeout=2,
                **options,
            )
            assert client.fetch_data() == {"keys": []}
        assert requests == [("http://jwks.invalid/keys", "forwarded")]


def test_empty_proxies_disable_discovery() -> None:
    with local_endpoint() as (url, requests):
        with (
            mock.patch(
                "urllib.request.getproxies",
                return_value={"http": "http://unreachable.invalid:9"},
            ),
            mock.patch("urllib.request.proxy_bypass", return_value=False),
        ):
            client = PyJWKClient(
                url + "/keys", cache_jwk_set=False, proxies={}, timeout=2
            )
            assert client.fetch_data() == {"keys": []}
        assert requests == [("/keys", None)]


def test_https_proxy_preserves_tls_and_redirect_policy() -> None:
    context = ssl.create_default_context()
    proxies = {"https": "http://proxy.invalid:8080"}
    client = PyJWKClient(
        "https://jwks.invalid/keys",
        cache_jwk_set=False,
        proxies=proxies,
        ssl_context=context,
    )
    proxies.clear()
    with mock.patch("urllib.request.build_opener") as build_opener:
        response = build_opener.return_value.open.return_value.__enter__.return_value
        response.read.return_value = '{"keys": []}'
        assert client.fetch_data() == {"keys": []}
    handlers = build_opener.call_args.args
    proxy_handler = next(
        h for h in handlers if isinstance(h, urllib.request.ProxyHandler)
    )
    https_handler = next(
        h for h in handlers if isinstance(h, urllib.request.HTTPSHandler)
    )
    assert vars(proxy_handler)["proxies"] == {"https": "http://proxy.invalid:8080"}
    assert vars(https_handler)["_context"] is context
    assert any(isinstance(h, _NoRedirectHandler) for h in handlers)
