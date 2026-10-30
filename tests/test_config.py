"""§4 config parsing and §10 selftest."""
from __future__ import annotations

import os
import shutil
from typing import Any

import pytest

from conftest import FakeDeps

import sentinel_heal as sh

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_shipped_heal_conf_parses(tmp_path: Any) -> None:
    p = tmp_path / "heal.conf"
    shutil.copy(os.path.join(REPO, "heal.conf"), p)
    os.chmod(p, 0o644)
    cfg = sh.load_config(str(p))
    assert cfg.dry_run is True and cfg.strikes == 2 and cfg.min_strike_gap_s == 50
    assert cfg.hold_units == ["sentinel-ops.service"]
    assert cfg.notify_conf == "/etc/sentinel-heal/notify.conf"
    names = {t.name: t for t in cfg.targets}
    assert set(names) == {"sentinel-agent", "ollama", "nginx"}
    assert (names["nginx"].host, names["nginx"].port, names["nginx"].path) == ("127.0.0.1", 80, "/")
    assert names["sentinel-agent"].requires_iface == "tailscale0"
    assert names["sentinel-agent"].busy_marker == "/run/sentinel/busy"
    assert names["ollama"].port == 11434 and names["ollama"].path == "/api/version"


def test_post_restart_wait_parsed(fd: FakeDeps) -> None:
    t = {t.name: t for t in fd.cfg().targets}
    assert t["ollama"].post_restart_wait_s == [15, 45]
    assert t["nginx"].post_restart_wait_s == [15]
    assert sh.parse_waits("x", "45,15") == [45, 15]
    with pytest.raises(sh.ConfigError):
        sh.parse_waits("x", "60,60")          # total > 90 s would overrun TimeoutStartSec=600
    with pytest.raises(sh.ConfigError):
        sh.parse_waits("x", "0")


def conf_with(fd: FakeDeps, old: str, new: str) -> None:
    text = open(fd.deps.paths.conf).read()
    assert old in text
    fd.write_conf(text=text.replace(old, new, 1))


def test_unknown_key_rejected(fd: FakeDeps) -> None:
    conf_with(fd, "strikes = 2", "strikes = 2\nstrike = 3")
    with pytest.raises(sh.ConfigError, match="unknown key"):
        fd.cfg()


def test_unknown_target_key_rejected(fd: FakeDeps) -> None:
    conf_with(fd, "unit = nginx.service", "unit = nginx.service\nshell = rm -rf /")
    with pytest.raises(sh.ConfigError, match="unknown key"):
        fd.cfg()


def test_unknown_section_rejected(fd: FakeDeps) -> None:
    conf_with(fd, "[target:nginx]", "[extra]\nx = 1\n\n[target:nginx]")
    with pytest.raises(sh.ConfigError, match="unknown section"):
        fd.cfg()


@pytest.mark.parametrize("url", ["http://localhost:80/", "http://127.0.0.2/", "https://127.0.0.1/",
                                 "http://user@127.0.0.1/", "http://0.0.0.0/", "http://127.0.0.1:99999/"])
def test_localhost_and_non_loopback_rejected(fd: FakeDeps, url: str) -> None:
    conf_with(fd, "probe = http://127.0.0.1:80/", "probe = " + url)
    with pytest.raises(sh.ConfigError):
        fd.cfg()


def test_bad_unit_rejected(fd: FakeDeps) -> None:
    conf_with(fd, "unit = nginx.service", "unit = nginx; reboot")
    with pytest.raises(sh.ConfigError):
        fd.cfg()


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX modes")
def test_group_writable_conf_rejected(fd: FakeDeps) -> None:
    os.chmod(fd.deps.paths.conf, 0o664)
    with pytest.raises(sh.ConfigError, match="writable"):
        fd.cfg()


@pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX modes")
def test_chmod_000_fails_run(fd: FakeDeps) -> None:
    """G9: chmod 000 heal.conf must fail the run even as root (root ignores DAC)."""
    os.chmod(fd.deps.paths.conf, 0o000)
    try:
        assert sh.cmd_run(fd.deps) == 1
    finally:
        os.chmod(fd.deps.paths.conf, 0o644)


def test_missing_notify_conf_noop(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)
    r = fd.unit_rows("nginx.service")[-1]
    assert r["outcome"] == "DRY_RUN" and r["notified"] is False
    assert fd.url.requests == []


def test_notify_conf_example_has_no_values() -> None:
    assert sh.load_notify(os.path.join(REPO, "notify.conf.example")) is None


def selftest_out(fd: FakeDeps, capsys: Any) -> tuple:
    rc = sh.main(["--selftest"], fd.deps)
    return rc, capsys.readouterr().out


def test_selftest_ok_and_prints_codes(fd: FakeDeps, capsys: Any) -> None:
    rc, out = selftest_out(fd, capsys)
    assert rc == 0, out
    assert "probe nginx: OK http:404" in out and "probe sentinel-agent: OK http:200" in out
    assert "notify: disabled" in out
    assert not [c for c in fd.sysd.calls if c[1] == "restart"]
    assert fd.rows() == []                       # writes nothing


def test_selftest_notify_mode_not_0600(fd: FakeDeps, capsys: Any) -> None:
    fd.write_notify()
    real = os.stat(os.path.join(fd.root, "etc", "notify.conf"))

    class FakeStat:
        st_mode = (real.st_mode & ~0o777) | 0o644
        st_uid = real.st_uid
    fd.deps.stat = lambda p: FakeStat()  # type: ignore[assignment,return-value]
    rc, out = selftest_out(fd, capsys)
    assert rc == 1 and "notify: ERROR" in out
    assert "ntfy.example" not in out and "secret" not in out


def test_selftest_notify_configured_hides_value(fd: FakeDeps, capsys: Any) -> None:
    fd.write_notify()
    rc, out = selftest_out(fd, capsys)
    assert rc == 0 and "notify: configured" in out and "ntfy.example" not in out


def test_selftest_rejects_localhost(fd: FakeDeps, capsys: Any) -> None:
    conf_with(fd, "probe = http://127.0.0.1:80/", "probe = http://localhost:80/")
    rc, out = selftest_out(fd, capsys)
    assert rc == 1 and "localhost rejected" in out


def test_selftest_missing_unit(fd: FakeDeps, capsys: Any) -> None:
    del fd.sysd.units["ollama.service"]
    rc, out = selftest_out(fd, capsys)
    assert rc == 1 and "unit ollama.service: ERROR not found" in out


def test_run_config_error_exit_1(fd: FakeDeps) -> None:
    conf_with(fd, "strikes = 2", "strikes = two")
    assert sh.cmd_run(fd.deps) == 1


def test_status_subcommand(fd: FakeDeps, capsys: Any) -> None:
    fd.run()
    capsys.readouterr()
    assert sh.main(["--status"], fd.deps) == 0
    assert '"last_run_ok": true' in capsys.readouterr().out


def test_agent_post_restart_waits(tmp_path: Any) -> None:
    p = tmp_path / "heal.conf"
    shutil.copy(os.path.join(REPO, "heal.conf"), p)
    os.chmod(p, 0o644)
    names = {t.name: t for t in sh.load_config(str(p)).targets}
    assert names["sentinel-agent"].post_restart_wait_s == [15, 30, 45]
