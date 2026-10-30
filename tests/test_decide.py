"""§5.1/§5.2 decision logic: skips, strikes, recovery, external restarts, hold_units."""
from __future__ import annotations

import errno
import os

from conftest import M0, FakeDeps, unit_props

import sentinel_heal as sh

NG = "nginx.service"
AG = "sentinel-agent.service"


def outcomes(fd: FakeDeps, unit: str) -> list:
    return [(r["outcome"], r["probe_reason"]) for r in fd.unit_rows(unit)]


def make_all_skip_conditions(fd: FakeDeps) -> None:
    """sentinel-agent matches every skip rule at once."""
    open(os.path.join(fd.root, "etc", "pause"), "w").close()
    fd.sysd.units["sentinel-ops.service"] = unit_props(ActiveState="activating")
    fd.deps.uptime = lambda: 10.0
    fd.sysd.units[AG].update(Result="start-limit-hit", ActiveState="failed", SubState="failed",
                             Job="restart", ActiveEnterTimestampMonotonic=str(int((M0 + 10_000) * 1e6)))
    fd.iface["tailscale0"] = None
    busy = os.path.join(fd.root, "sentinel", "busy")
    open(busy, "w").close()
    os.utime(busy, (fd.clock.t - 5, fd.clock.t - 5))
    fd.probe.by_port[3000] = 503


def test_skip_order(fd: FakeDeps) -> None:
    make_all_skip_conditions(fd)
    expected = ["paused", "hold:sentinel-ops", "boot-grace", "start-limit-hit", "not-active:failed/failed",
                "pending-job:restart", "recently-started", "iface-down:tailscale0", "busy"]
    removers = [
        lambda: os.remove(os.path.join(fd.root, "etc", "pause")),
        lambda: fd.sysd.units.pop("sentinel-ops.service"),
        lambda: setattr(fd.deps, "uptime", lambda: 86400.0),
        lambda: fd.sysd.units[AG].update(Result="success"),
        lambda: fd.sysd.units[AG].update(ActiveState="active", SubState="running"),
        lambda: fd.sysd.units[AG].update(Job=""),
        lambda: fd.sysd.units[AG].update(ActiveEnterTimestampMonotonic=str(int((M0 - 3600) * 1e6))),
        lambda: fd.iface.update(tailscale0="100.64.0.1"),
        lambda: None,
    ]
    for want, remove in zip(expected, removers):
        assert fd.run(60) == 0
        last = fd.unit_rows(AG)[-1]
        assert last["probe_reason"] == want
        assert last["outcome"] == ("UNKNOWN" if want == "busy" else "SKIPPED")
        assert last["action"] == "none"
        remove()
    assert fd.sysd.restart_calls() == []
    assert not any(c[1:3] == ["--no-block", AG] for c in fd.sysd.calls)


def test_strikes_0_1_2(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = ConnectionRefusedError(errno.ECONNREFUSED, "x")
    fd.run()
    assert outcomes(fd, NG) == [("DOWN1", "econnrefused")]
    assert fd.state()[NG]["strikes"] == 1
    fd.run(60)
    assert outcomes(fd, NG)[-1] == ("DRY_RUN", "econnrefused")
    assert fd.state()[NG]["strikes"] == 0
    assert fd.unit_rows("ollama.service") == []      # OK units are silent


def test_stale_window_resets(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(181)
    assert [o for o, _ in outcomes(fd, NG)] == ["DOWN1", "DOWN1"]
    assert fd.sysd.restart_calls() == []


def test_min_strike_gap(fd: FakeDeps) -> None:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(30)                                  # manual re-run too soon: not counted, no row
    assert [o for o, _ in outcomes(fd, NG)] == ["DOWN1"]
    assert fd.state()[NG]["strikes"] == 1
    fd.run(25)                                  # 55 s after first DOWN >= 50 s gap
    assert outcomes(fd, NG)[-1][0] == "DRY_RUN"


def test_unknown_never_strikes(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = PermissionError(errno.EPERM, "x")
    for _ in range(5):
        fd.run(60)
    assert outcomes(fd, NG) == [("UNKNOWN", "eperm")]   # one row per reason change
    assert fd.state()[NG]["strikes"] == 0
    assert fd.sysd.restart_calls() == []


def test_recovered_row(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()
    fd.probe.by_port[80] = 404
    fd.run(60)
    rows = fd.unit_rows(NG)
    assert [r["outcome"] for r in rows] == ["DOWN1", "RECOVERED"]
    assert rows[-1]["probe"] == "OK" and rows[-1]["strikes"] == 0
    fd.run(60)
    assert len(fd.unit_rows(NG)) == 2


def test_skip_rows_only_on_reason_change(fd: FakeDeps) -> None:
    pause = os.path.join(fd.root, "run", "pause")
    open(pause, "w").close()
    for _ in range(3):
        fd.run(60)
    assert outcomes(fd, NG) == [("SKIPPED", "paused")]
    fd.sysd.units[NG].update(ActiveState="inactive", SubState="dead")
    fd.run(60)
    assert outcomes(fd, NG) == [("SKIPPED", "paused")]     # still paused: first match wins
    os.remove(pause)
    fd.run(60)
    fd.run(60)
    assert outcomes(fd, NG)[-1] == ("SKIPPED", "not-active:inactive/dead")
    assert len(fd.unit_rows(NG)) == 2


def test_skip_keeps_strikes(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()
    fd.sysd.units[NG]["Job"] = "reload"
    fd.run(60)
    assert outcomes(fd, NG)[-1] == ("SKIPPED", "pending-job:reload")
    assert fd.state()[NG]["strikes"] == 1


def test_external_restart(fd: FakeDeps) -> None:
    fd.write_notify()
    fd.probe.by_port[80] = 503
    fd.run()
    assert fd.state()[NG]["strikes"] == 1
    fd.url.requests.clear()
    fd.sysd.units[NG].update(InvocationID="inv-new", MainPID="999",
                             ActiveEnterTimestampMonotonic=str(int((M0 + 60) * 1e6)))
    fd.run(70)
    rows = fd.unit_rows(NG)
    ext = [r for r in rows if r["outcome"] == "EXTERNAL_RESTART"]
    assert len(ext) == 1
    e = ext[0]
    assert e["action"] == "none" and e["old_inv"] == "inv-nginx" and e["new_inv"] == "inv-new"
    assert e["old_pid"] == 300 and e["new_pid"] == 999 and e["strikes"] == 0
    assert rows[-1]["probe_reason"] == "recently-started"
    assert fd.state()[NG]["strikes"] == 0
    assert fd.url.requests == []                          # no notify
    assert sh.count_actions(fd.rows(), NG, fd.clock.t) == (0, 0)   # not counted in caps
    fd.run(60)
    assert len([r for r in fd.unit_rows(NG) if r["outcome"] == "EXTERNAL_RESTART"]) == 1


def test_no_external_restart_on_first_run(fd: FakeDeps) -> None:
    fd.run()
    assert fd.rows() == []


def test_hold_units_active_skips_all(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()
    assert fd.state()[NG]["strikes"] == 1
    for st in ("active", "activating", "deactivating"):
        fd.sysd.units["sentinel-ops.service"] = unit_props(ActiveState=st)
        fd.run(60)
        for u in (AG, "ollama.service", NG):
            assert fd.unit_rows(u)[-1]["outcome"] == "SKIPPED"
            assert fd.unit_rows(u)[-1]["probe_reason"] == "hold:sentinel-ops"
            assert fd.state()[u]["strikes"] == 0
    assert fd.sysd.restart_calls() == []
    assert all(c[1] != "restart" for c in fd.sysd.calls)


def test_missing_hold_unit_not_held(fd: FakeDeps) -> None:
    assert "sentinel-ops.service" not in fd.sysd.units
    r = fd.runner()
    assert r.held is None


def test_hold_show_failure_counts_as_held(fd: FakeDeps) -> None:
    fd.sysd.fail_show.add("sentinel-ops.service")
    assert fd.runner().held == "sentinel-ops.service"


def test_held_rechecked_before_restart(fd: FakeDeps) -> None:
    fd.probe.by_port[80] = 503
    fd.run()

    def flip(unit: str) -> None:
        if unit == NG:
            fd.sysd.units["sentinel-ops.service"] = unit_props(ActiveState="activating")
    fd.sysd.on_show = flip
    fd.run(60)
    assert outcomes(fd, NG)[-1] == ("SKIPPED", "hold:sentinel-ops")
    assert fd.sysd.restart_calls() == []
    assert fd.state()[NG]["strikes"] == 0


def test_show_failure_is_unknown(fd: FakeDeps) -> None:
    fd.sysd.fail_show.add(NG)
    fd.run()
    fd.run(60)
    assert outcomes(fd, NG) == [("UNKNOWN", "systemctl-show-failed")]
    assert not any(p[1] == 80 for p in fd.probe.calls)


def test_kill_file_exits_without_rows(fd: FakeDeps) -> None:
    open(os.path.join(fd.root, "etc", "KILL"), "w").close()
    fd.probe.by_port[80] = 503
    assert fd.run() == 0
    assert fd.rows() == [] and fd.sysd.calls == []


def test_status_json_written(fd: FakeDeps) -> None:
    fd.run()
    s = sh.load_json(os.path.join(fd.root, "lib", "status.json"))
    assert s["last_run_ok"] is True and s["dry_run"] is False
    assert set(s["units"]) == {AG, "ollama.service", NG}
    assert s["units"][NG]["probe"] == "OK"


def test_hold_unit_reloading_is_held(fd: FakeDeps) -> None:
    fd.sysd.units["sentinel-ops.service"] = unit_props(ActiveState="reloading")
    assert fd.runner().held == "sentinel-ops.service"


def test_external_restart_logged_after_activating(fd: FakeDeps) -> None:
    """restart-self: a tick that sees the unit 'activating' with a new invocation must not
    swallow the change; EXTERNAL_RESTART is logged once the unit is active."""
    fd.run()
    assert fd.state()[AG]["last_inv"] == "inv-sentinel-agent"
    fd.sysd.units[AG].update(ActiveState="activating", SubState="start", InvocationID="inv-new",
                             MainPID="777")
    fd.run(60)
    assert fd.state()[AG]["last_inv"] == "inv-sentinel-agent"
    assert not [r for r in fd.unit_rows(AG) if r["outcome"] == "EXTERNAL_RESTART"]
    fd.sysd.units[AG].update(ActiveState="active", SubState="running",
                             ActiveEnterTimestampMonotonic=str(int((M0 + 100) * 1e6)))
    fd.run(60)
    ext = [r for r in fd.unit_rows(AG) if r["outcome"] == "EXTERNAL_RESTART"]
    assert len(ext) == 1
    assert ext[0]["old_inv"] == "inv-sentinel-agent" and ext[0]["new_inv"] == "inv-new"
    assert fd.state()[AG]["last_inv"] == "inv-new"
    fd.run(60)
    assert len([r for r in fd.unit_rows(AG) if r["outcome"] == "EXTERNAL_RESTART"]) == 1
