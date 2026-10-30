"""§6 probe classification: every row of the table."""
from __future__ import annotations

import errno
import http.client
import socket
from typing import Any

import pytest

import sentinel_heal as sh


def probe_raising(exc: Any):
    def f(host: str, port: int, path: str, timeout: float) -> int:
        if isinstance(exc, int):
            return exc
        raise exc
    return f


@pytest.mark.parametrize("value,cls,reason", [
    (100, "OK", "http:100"),
    (200, "OK", "http:200"),
    (301, "OK", "http:301"),
    (401, "OK", "http:401"),
    (404, "OK", "http:404"),
    (499, "OK", "http:499"),
    (500, "DOWN", "http:500"),
    (503, "DOWN", "http:503"),
    (599, "DOWN", "http:599"),
    (ConnectionRefusedError(errno.ECONNREFUSED, "x"), "DOWN", "econnrefused"),
    (ConnectionResetError(errno.ECONNRESET, "x"), "DOWN", "econnreset"),
    (http.client.RemoteDisconnected("x"), "DOWN", "econnreset"),
    (socket.timeout("timed out"), "DOWN", "timeout"),
    (TimeoutError("x"), "DOWN", "timeout"),
    (PermissionError(errno.EPERM, "x"), "UNKNOWN", "eperm"),
    (PermissionError(errno.EACCES, "x"), "UNKNOWN", "eperm"),
    (OSError(errno.EMFILE, "x"), "UNKNOWN", "errno:EMFILE"),
    (OSError(errno.ENFILE, "x"), "UNKNOWN", "errno:ENFILE"),
    (OSError(errno.ENOBUFS, "x"), "UNKNOWN", "errno:ENOBUFS"),
    (OSError(errno.ENOMEM, "x"), "UNKNOWN", "errno:ENOMEM"),
    (OSError(errno.EHOSTUNREACH, "x"), "UNKNOWN", "errno:EHOSTUNREACH"),
    (OSError(errno.ENETUNREACH, "x"), "UNKNOWN", "errno:ENETUNREACH"),
    (OSError(errno.EADDRNOTAVAIL, "x"), "UNKNOWN", "errno:EADDRNOTAVAIL"),
    (socket.gaierror(-2, "x"), "UNKNOWN", "dns"),
    (http.client.BadStatusLine("x"), "UNKNOWN", "http-garbage"),
    (http.client.LineTooLong("x"), "UNKNOWN", "http-garbage"),
    (OSError(errno.EIO, "x"), "UNKNOWN", "errno:EIO"),
    (ValueError("weird"), "UNKNOWN", "error:ValueError"),
    (99, "UNKNOWN", "http-garbage"),
    (600, "UNKNOWN", "http-garbage"),
])
def test_classify_table(value: Any, cls: str, reason: str) -> None:
    assert sh.classify(probe_raising(value), "127.0.0.1", 80, "/", 5) == (cls, reason)


def test_http_status_reads_status_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    class Resp:
        status = 404

        def read(self, *a: Any) -> bytes:  # pragma: no cover - must never be called
            raise AssertionError("body read")

    class Conn:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            seen.update(host=host, port=port, timeout=timeout)

        def request(self, method: str, path: str, headers: dict) -> None:
            seen.update(method=method, path=path, headers=headers)

        def getresponse(self) -> Resp:
            return Resp()

        def close(self) -> None:
            seen["closed"] = True

    monkeypatch.setattr(sh.http.client, "HTTPConnection", Conn)
    assert sh.http_status("127.0.0.1", 80, "/", 5) == 404
    assert seen["method"] == "GET" and seen["closed"] and seen["timeout"] == 5
    assert seen["headers"] == {"Host": "127.0.0.1", "Connection": "close", "User-Agent": "sentinel-heal"}
