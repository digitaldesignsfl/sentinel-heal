"""§8.1 JSONL row schema and §8.3 status.json."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, List

import pytest

from conftest import FakeDeps

import sentinel_heal as sh

NG = "nginx.service"
REQUIRED = {"v", "ts", "run_id", "unit", "probe", "probe_reason", "action", "outcome", "strikes",
            "old_pid", "new_pid", "old_inv", "new_inv", "nrestarts", "unit_sha256", "dry_run", "dur_ms"}
OPTIONAL = {"job_pending", "caps", "notified", "would_restart"}


def test_row_has_exactly_schema_keys(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)
    rows = fd.unit_rows(NG)
    assert [r["outcome"] for r in rows] == ["DOWN1", "DRY_RUN"]
    for r in rows:
        assert REQUIRED <= set(r) <= REQUIRED | OPTIONAL
        assert r["v"] == 1 and r["run_id"] == "run1"
        assert sh.TS_RE.match(r["ts"])
        assert len(r["unit_sha256"]) == 64
        assert isinstance(r["dur_ms"], int) and isinstance(r["strikes"], int)
    assert "job_pending" not in rows[1]
    assert rows[1]["caps"] == {"hour": 0, "day": 0}


def test_ensure_ascii_one_line_and_fsync(fd: FakeDeps) -> None:
    calls: List[int] = []
    path = os.path.join(fd.root, "log", "x.jsonl")
    sh.append_row(path, {"a": "café\nline2", "b": 1}, calls.append)
    raw = open(path, "rb").read()
    assert raw.count(b"\n") == 1 and raw.endswith(b"\n")
    assert b"\\u00e9" in raw and b"\\n" in raw
    raw.decode("ascii")
    assert len(calls) == 1
    assert json.loads(raw) == {"a": "café\nline2", "b": 1}


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX modes")
def test_jsonl_mode_0640(fd: FakeDeps) -> None:
    old = os.umask(0)
    try:
        p = os.path.join(fd.root, "log", "m.jsonl")
        sh.append_row(p, {"x": 1}, lambda fd_: None)
        assert os.stat(p).st_mode & 0o777 == 0o640
    finally:
        os.umask(old)


def test_status_atomic_tmp_then_rename(fd: FakeDeps, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: List[Any] = []
    real_replace = os.replace

    def spy(src: str, dst: str) -> None:
        seen.append((src, dst, os.path.exists(src), open(src).read()))
        real_replace(src, dst)
    monkeypatch.setattr(sh.os, "replace", spy)
    fd.run()
    status = os.path.join(fd.root, "lib", "status.json")
    st = [s for s in seen if s[1] == status]
    assert len(st) == 1
    src, dst, existed, content = st[0]
    assert existed and src.startswith(status + ".tmp.")
    assert json.loads(content)["v"] == 1
    assert not os.path.exists(src)
    if hasattr(os, "fchmod"):
        assert os.stat(status).st_mode & 0o777 == 0o644


def test_status_size_and_recent_projection(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    for _ in range(8):
        fd.run(200)        # every run is a fresh DOWN1 (stale window): many rows
    status = os.path.join(fd.root, "lib", "status.json")
    raw = open(status, "rb").read()
    assert len(raw) <= 8192
    s = json.loads(raw)
    assert len(s["recent"]) == 5
    for r in s["recent"]:
        assert set(r) == {"ts", "unit", "action", "outcome", "probe_reason"}
    assert set(s) == {"v", "ts", "dry_run", "paused", "killed", "last_run_ok", "units", "recent"}
    assert set(s["units"][NG]) == {"probe", "strikes", "last_outcome", "last_action_ts", "external_restarts_24h"}


def test_no_free_text_from_systemd_in_rows(fd: FakeDeps) -> None:
    fd.sysd.units[NG].update(ActiveState="evil text\nwith newline", SubState="x")
    fd.run()
    r = fd.unit_rows(NG)[-1]
    assert r["probe_reason"] == "not-active:other/x"


def test_syslog_line_per_row(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()
    assert any(l.startswith("nginx.service DOWN1 ") for l in fd.logs)


def test_stdlib_only() -> None:
    code = ("import sys, sysconfig, os; sys.path.insert(0, sys.argv[1]); before=set(sys.modules);"
            "import sentinel_heal; std=sysconfig.get_paths()['stdlib'];"
            "bad=[n for n in set(sys.modules)-before if n!='sentinel_heal' and "
            "getattr(sys.modules[n],'__file__',None) and not os.path.realpath(sys.modules[n].__file__)"
            ".startswith(os.path.realpath(std))]; print(','.join(sorted(bad))); sys.exit(1 if bad else 0)")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, "-I", "-c", code, here], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
