"""§5.2 caps computed from heal.jsonl rolling windows."""
from __future__ import annotations

import json
from typing import List

from conftest import FakeDeps

import sentinel_heal as sh

NG = "nginx.service"


def seed(fd: FakeDeps, ages_s: List[float], outcome: str = "VERIFIED", action: str = "restart",
         unit: str = NG) -> None:
    with open(fd.log_path, "a") as f:
        for a in ages_s:
            f.write(json.dumps({"v": 1, "ts": sh.utc_ts(fd.clock.t - a), "unit": unit,
                                "action": action, "outcome": outcome}) + "\n")


def drive_to_decision(fd: FakeDeps) -> dict:
    fd.write_conf(dry=1)
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)
    return fd.unit_rows(NG)[-1]


def test_three_in_hour_capped(fd: FakeDeps) -> None:
    fd.write_notify()
    seed(fd, [600, 1200, 1800])
    r = drive_to_decision(fd)
    assert r["outcome"] == "CAPPED" and r["action"] == "none"
    assert r["caps"] == {"hour": 3, "day": 3}
    assert fd.state()[NG]["strikes"] == 0
    assert fd.url.requests[-1].get_header("Title") == "sentinel-heal capped"
    assert fd.sysd.restart_calls() == []


def test_dry_timeout_rows_count(fd: FakeDeps) -> None:
    seed(fd, [600], "DRY_RUN", action="dry_run_restart")
    seed(fd, [900], "TIMEOUT")
    seed(fd, [1200], "DRY_RUN", action="dry_run_restart")
    assert sh.count_actions(sh.read_rows(fd.log_path), NG, fd.clock.t, dry_run=True) == (3, 3)
    assert drive_to_decision(fd)["outcome"] == "CAPPED"


def test_non_restart_rows_do_not_count(fd: FakeDeps) -> None:
    seed(fd, [60, 120, 180], "EXTERNAL_RESTART", action="none")
    seed(fd, [60, 120, 180], "SKIPPED", action="alert")
    seed(fd, [60, 120, 180], unit="ollama.service")
    assert sh.count_actions(sh.read_rows(fd.log_path), NG, fd.clock.t) == (0, 0)


def test_verified_61_min_ago_does_not_count(fd: FakeDeps) -> None:
    seed(fd, [600, 1200, 61 * 60])
    assert sh.count_actions(sh.read_rows(fd.log_path), NG, fd.clock.t) == (2, 3)
    assert drive_to_decision(fd)["outcome"] == "DRY_RUN"


def test_day_cap(fd: FakeDeps) -> None:
    seed(fd, [2 * 3600, 4 * 3600, 6 * 3600, 8 * 3600, 10 * 3600, 23 * 3600])
    seed(fd, [25 * 3600])
    assert sh.count_actions(sh.read_rows(fd.log_path), NG, fd.clock.t) == (0, 6)
    r = drive_to_decision(fd)
    assert r["outcome"] == "CAPPED" and r["caps"] == {"hour": 0, "day": 6}


def test_garbage_lines_ignored(fd: FakeDeps) -> None:
    with open(fd.log_path, "w") as f:
        f.write("not json\n[1,2]\n{\"unit\":\"nginx.service\",\"action\":\"restart\",\"ts\":\"bad\"}\n")
    assert sh.count_actions(sh.read_rows(fd.log_path), NG, fd.clock.t) == (0, 0)


def test_capped_row_counts_and_waits_two_runs(fd: FakeDeps) -> None:
    seed(fd, [600, 1200, 1800])
    drive_to_decision(fd)
    fd.run(60)
    assert fd.unit_rows(NG)[-1]["outcome"] == "DOWN1"    # strikes reset after CAPPED


def test_capped_rows_do_not_count(fd: FakeDeps) -> None:
    seed(fd, [60, 120, 180], "CAPPED", action="none")
    rows = sh.read_rows(fd.log_path)
    assert sh.count_actions(rows, NG, fd.clock.t) == (0, 0)
    assert sh.count_actions(rows, NG, fd.clock.t, dry_run=True) == (0, 0)


def test_dry_run_rows_count_only_in_dry_mode(fd: FakeDeps) -> None:
    seed(fd, [60, 120, 180], "DRY_RUN", action="dry_run_restart")
    rows = sh.read_rows(fd.log_path)
    assert sh.count_actions(rows, NG, fd.clock.t, dry_run=True) == (3, 3)
    assert sh.count_actions(rows, NG, fd.clock.t, dry_run=False) == (0, 0)


def test_persistent_outage_not_locked_out(fd: FakeDeps) -> None:
    fd.write_notify()
    seed(fd, [600, 1200, 1800])
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)
    assert fd.unit_rows(NG)[-1]["outcome"] == "CAPPED"
    for _ in range(80):          # 80 min of DOWN, 60 s ticks
        fd.run(60)
        if fd.sysd.restart_calls():
            break
    # seeds age 600/1200/1800 s: all out of the hour window once 1800 + 3600 s have passed
    assert len([r for r in fd.unit_rows(NG) if r["outcome"] == "CAPPED"]) == 1
    assert len(fd.sysd.restart_calls()) == 1


def test_live_to_dry_switch_does_not_inherit_dry_caps(fd: FakeDeps) -> None:
    fd.write_notify()
    seed(fd, [60, 120, 180], "DRY_RUN", action="dry_run_restart")
    fd.probe.by_port[80] = 503
    fd.run()
    fd.run(60)
    assert fd.unit_rows(NG)[-1]["outcome"] != "CAPPED"
    assert len(fd.sysd.restart_calls()) == 1
