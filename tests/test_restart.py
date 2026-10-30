"""§5.2 act: restart job polling, verification, TIMEOUT, ollama second sample, DRY_RUN."""
from __future__ import annotations

from conftest import FakeDeps, unit_props

import sentinel_heal as sh

NG = "nginx.service"
OL = "ollama.service"


def two_strikes(fd: FakeDeps, port: int) -> None:
    fd.probe.by_port[port] = 503
    fd.run()
    fd.run(60)


def last(fd: FakeDeps, unit: str) -> dict:
    return fd.unit_rows(unit)[-1]


def test_job_clears_pid_changed_verified(fd: FakeDeps) -> None:
    fd.write_notify()
    after = unit_props(MainPID=301, InvocationID="inv-x", NRestarts=0)
    fd.sysd.after_restart[NG] = [unit_props(Job="restart", ActiveState="deactivating"), after]
    fd.probe.by_port[80] = [503, 503, 404]
    fd.run()
    fd.run(60)
    r = last(fd, NG)
    assert r["outcome"] == "VERIFIED" and r["action"] == "restart" and r["probe"] == "OK"
    assert r["old_pid"] == 300 and r["new_pid"] == 301 and r["old_inv"] == "inv-nginx" and r["new_inv"] == "inv-x"
    assert r["caps"] == {"hour": 0, "day": 0} and r["notified"] is True
    assert fd.sysd.restart_calls() == [["systemctl", "restart", "--no-block", NG]]
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal restart_verified"
    # next tick: own restart is not reported as EXTERNAL_RESTART
    fd.run(60)
    assert not [x for x in fd.unit_rows(NG) if x["outcome"] == "EXTERNAL_RESTART"]


def test_job_clears_pid_same_failed(fd: FakeDeps) -> None:
    fd.write_notify()
    fd.sysd.after_restart[NG] = [unit_props(MainPID=300, InvocationID="inv-x")]
    fd.probe.by_port[80] = [503, 503, 404]
    fd.run()
    fd.run(60)
    r = last(fd, NG)
    assert r["outcome"] == "FAILED" and r["probe"] == "OK" and r["new_pid"] == 300


def test_active_state_failed_failed(fd: FakeDeps) -> None:
    fd.write_notify()
    fd.sysd.after_restart[NG] = [unit_props(ActiveState="failed", SubState="failed", Result="exit-code",
                                            MainPID=0, InvocationID="inv-x")]
    two_strikes(fd, 80)
    r = last(fd, NG)
    assert r["outcome"] == "FAILED" and r["probe_reason"] == "post-restart:failed/exit-code"
    assert fd.state()[NG]["strikes"] == 0


def test_job_never_clears_timeout(fd: FakeDeps) -> None:
    fd.write_notify()
    fd.sysd.after_restart[NG] = [unit_props(Job="restart", ActiveState="deactivating")]
    two_strikes(fd, 80)
    r = last(fd, NG)
    assert r["outcome"] == "TIMEOUT" and r["job_pending"] is True and r["outcome"] != "FAILED"
    # nginx: 5 s stop + 90 s start + 10 s grace = 105 s budget polled every 2 s
    assert sum(fd.clock.sleeps) >= 105 and sum(fd.clock.sleeps) <= 110
    fd.run(60)
    # §5.2 order: not-active precedes pending-job, so a stuck stop reads not-active:deactivating
    # (the §11.2 G3 text says pending-job; either way it is a SKIPPED row and no second restart)
    assert last(fd, NG)["outcome"] == "SKIPPED"
    assert last(fd, NG)["probe_reason"] == "not-active:deactivating/running"
    assert len(fd.sysd.restart_calls()) == 1
    # job finishes later: heal's own restart is not an EXTERNAL_RESTART
    fd.sysd.after_restart[NG] = [unit_props(MainPID=302, InvocationID="inv-y")]
    fd.run(60)
    assert not [x for x in fd.unit_rows(NG) if x["outcome"] == "EXTERNAL_RESTART"]


def test_ollama_second_sample_at_45s(fd: FakeDeps) -> None:
    fd.write_notify()
    after = unit_props(MainPID=201, InvocationID="inv-o2")
    fd.sysd.after_restart[OL] = [after]
    fd.probe.by_port[11434] = [503, 503, ConnectionRefusedError(), 200]
    fd.run()
    fd.run(60)
    r = last(fd, OL)
    assert r["outcome"] == "VERIFIED" and r["probe_reason"] == "http:200"
    ol_probes = [c for c in fd.probe.calls if c[1] == 11434]
    assert len(ol_probes) == 4
    # after the job poll: sleep 15, then sleep 45 more (§5.2 pseudocode, sequential)
    assert fd.clock.sleeps[-2:] == [15, 45]


def test_ollama_both_samples_fail(fd: FakeDeps) -> None:
    fd.write_notify()
    fd.sysd.after_restart[OL] = [unit_props(MainPID=201, InvocationID="inv-o2")]
    fd.probe.by_port[11434] = 503
    fd.run()
    fd.run(60)
    r = last(fd, OL)
    assert r["outcome"] == "FAILED" and r["probe"] == "DOWN"


def test_dry_run_no_restart_command(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.write_notify()
    two_strikes(fd, 80)
    r = last(fd, NG)
    assert r["outcome"] == "DRY_RUN" and r["action"] == "dry_run_restart" and r["would_restart"] is True
    assert r["dry_run"] is True
    assert fd.sysd.restart_calls() == []
    assert all(c[1] != "restart" for c in fd.sysd.calls)
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal dry_run_restart"


def test_timespan_parse() -> None:
    assert sh.parse_timespan("1min 30s") == 90
    assert sh.parse_timespan("5s") == 5
    assert sh.parse_timespan("100ms") == 0.1
    assert sh.parse_timespan("90000000") == 90
    assert sh.parse_timespan("infinity") is None
    assert sh.parse_timespan("") is None


def test_live_blocked_without_notify(fd: FakeDeps) -> None:
    fd.write_conf(dry=0)          # no notify.conf written
    two_strikes(fd, 80)
    r = last(fd, NG)
    assert r["outcome"] == "DRY_RUN" and r["dry_run"] is True
    assert fd.sysd.restart_calls() == []
    fd.run(60)
    fd.run(60)
    assert len([m for m in fd.logs if "live restarts BLOCKED" in m]) == 1
