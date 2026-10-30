"""§9 notify: headers, secrecy, de-dup, failure handling."""
from __future__ import annotations

import os
import urllib.error
from typing import Any

from conftest import FakeDeps

import sentinel_heal as sh

_RealHealConf = sh.HealConf

URL = "https://ntfy.example.invalid/secret-topic-xyz"
TOKEN = "tok-SECRET-123"
NG = "nginx.service"


def all_text(fd: FakeDeps) -> str:
    log = open(fd.log_path).read() if os.path.exists(fd.log_path) else ""
    status = open(os.path.join(fd.root, "lib", "status.json")).read() \
        if os.path.exists(os.path.join(fd.root, "lib", "status.json")) else ""
    return "\n".join(fd.logs) + log + status


def trigger_dry(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)


def test_bearer_only_when_token_set(fd: FakeDeps) -> None:
    fd.write_notify(URL, "")
    trigger_dry(fd)
    req = fd.url.requests[-1]
    assert req.get_header("Authorization") is None
    assert req.full_url == URL and req.get_method() == "POST"
    assert req.get_header("Priority") == "3"
    assert req.data == b"[sentinel-heal] dry_run_restart nginx.service DRY_RUN http:503"


def test_bearer_when_token(fd: FakeDeps) -> None:
    fd.write_notify(URL, TOKEN)
    trigger_dry(fd)
    assert fd.url.requests[-1].get_header("Authorization") == "Bearer " + TOKEN


def test_url_never_in_rows_or_syslog(fd: FakeDeps) -> None:
    fd.write_notify(URL, TOKEN)
    fd.url.fail = urllib.error.URLError(URL + " " + TOKEN)
    trigger_dry(fd)
    text = all_text(fd)
    assert "secret-topic" not in text and "ntfy.example" not in text and TOKEN not in text


def test_failure_is_row_not_exception(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    fd.url.fail = urllib.error.URLError("boom")
    trigger_dry(fd)
    rows = fd.unit_rows("sentinel-heal.service")
    assert rows and rows[-1]["outcome"] == "UNKNOWN"
    assert rows[-1]["probe_reason"] == "notify-failed:URLError"
    assert fd.unit_rows(NG)[-1]["outcome"] == "DRY_RUN" and fd.unit_rows(NG)[-1]["notified"] is False
    assert sh.load_json(os.path.join(fd.root, "lib", "status.json"))["last_run_ok"] is True


def test_dedup_window(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    r = sh.Runner(fd.cfg(), fd.deps)
    assert r.notify("capped", NG, "CAPPED", "x") is True
    fd.clock.advance(1000)
    assert r.notify("capped", NG, "CAPPED", "x") is False
    assert r.notify("capped", "ollama.service", "CAPPED", "x") is True   # different key
    fd.clock.advance(2601)
    assert r.notify("capped", NG, "CAPPED", "x") is True
    assert len(fd.url.requests) == 3


def test_dedup_persists_across_runs(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    assert sh.Runner(fd.cfg(), fd.deps).notify("capped", NG, "CAPPED", "x") is True
    assert sh.Runner(fd.cfg(), fd.deps).notify("capped", NG, "CAPPED", "x") is False


def test_verified_and_failed_never_suppressed(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    r = sh.Runner(fd.cfg(), fd.deps)
    for _ in range(3):
        assert r.notify("restart_verified", NG, "VERIFIED", "http:200") is True
        assert r.notify("restart_failed", NG, "FAILED", "x") is True
    assert fd.url.requests[-1].get_header("Priority") == "4"


def test_disabled_logs_once(fd: FakeDeps) -> None:
    r = sh.Runner(fd.cfg(), fd.deps)
    assert r.notify("capped", NG, "CAPPED", "x") is False
    assert r.notify("unit_failed", NG, "SKIPPED", "x") is False
    assert sum("notify: disabled" in l for l in fd.logs) == 1
    assert fd.url.requests == []


def test_alert_unit_heal_failed(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    fd.sysd.units["sentinel-heal.service"] = {"ActiveState": "failed", "Result": "exit-code",
                                              "NRestarts": "0", "ExecMainStatus": "1"}
    assert sh.main(["--alert-unit", "sentinel-heal.service"], fd.deps) == 0
    r = fd.unit_rows("sentinel-heal.service")[-1]
    assert r["action"] == "alert" and r["outcome"] == "SKIPPED" and r["probe_reason"] == "onfailure:exit-code"
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal heal_failed"


def test_alert_unit_target(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    fd.sysd.units[NG].update(ActiveState="failed", Result="start-limit-hit")
    assert sh.main(["--alert-unit", NG], fd.deps) == 0
    assert fd.unit_rows(NG)[-1]["probe_reason"] == "onfailure:start-limit-hit"
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal unit_failed"


def test_alert_unit_rejects_bad_name(fd: FakeDeps) -> None:
    assert sh.main(["--alert-unit", "../../etc/passwd"], fd.deps) == 2
    assert fd.sysd.calls == []


def test_alert_unit_works_when_conf_broken(fd: FakeDeps, monkeypatch: Any) -> None:
    """G9: heal.conf broken -> heal fails -> heal-alert@ must still alert using defaults."""
    fd.write_notify(URL)
    fd.write_conf(text="[heal]\nbogus = 1\n")
    root = fd.root
    monkeypatch.setattr(sh, "HealConf", lambda: _defaults(root))
    fd.sysd.units["sentinel-heal.service"] = {"ActiveState": "failed", "Result": "exit-code", "NRestarts": "0"}
    assert sh.main(["--alert-unit", "sentinel-heal.service"], fd.deps) == 0
    assert fd.unit_rows("sentinel-heal.service")[-1]["probe_reason"] == "onfailure:exit-code"
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal heal_failed"


def _defaults(root: str) -> "sh.HealConf":
    c = _RealHealConf()
    c.log_path = os.path.join(root, "log", "heal.jsonl")
    c.run_dir = os.path.join(root, "run")
    c.status_path = os.path.join(root, "lib", "status.json")
    c.notify_conf = os.path.join(root, "etc", "notify.conf")
    return c


def test_start_limit_hit_notifies(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    fd.sysd.units[NG].update(Result="start-limit-hit", ActiveState="failed")
    fd.run()
    r = fd.unit_rows(NG)[-1]
    assert r["outcome"] == "SKIPPED" and r["probe_reason"] == "start-limit-hit" and r["notified"] is True
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal start_limit_hit"


def test_unknown_persistent(fd: FakeDeps) -> None:
    fd.write_notify(URL)
    fd.probe.by_port[80] = PermissionError(1, "x")
    fd.run()
    fd.run(1000)
    assert fd.url.requests == []
    fd.run(1000)
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal unknown_persistent"
    fd.run(60)
    assert len(fd.url.requests) == 1
