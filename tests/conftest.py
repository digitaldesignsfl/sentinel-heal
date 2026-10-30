"""Shared fixtures: FakeDeps (fake systemd, clock, probe, urlopen) and a tmp heal.conf."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sentinel_heal as sh  # noqa: E402

T0 = 1_761_700_000.0          # wall clock start (2025-10-29)
M0 = 100_000.0                # monotonic start (s)


def unit_props(**over: Any) -> Dict[str, str]:
    p = {"ActiveState": "active", "SubState": "running", "Result": "success", "Job": "",
         "MainPID": "100", "InvocationID": "inv-a", "NRestarts": "0",
         "ActiveEnterTimestampMonotonic": str(int((M0 - 3600) * 1e6)),
         "TimeoutStopUSec": "1min 30s", "TimeoutStartUSec": "1min 30s",
         "LoadState": "loaded", "ExecMainStatus": "0"}
    p.update({k: str(v) for k, v in over.items()})
    return p


class FakeClock:
    def __init__(self) -> None:
        self.t, self.m = T0, M0
        self.sleeps: List[float] = []

    def time(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.m

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.advance(s)

    def advance(self, s: float) -> None:
        self.t += s
        self.m += s


class FakeSystemd:
    """Answers `systemctl show|cat|restart`. After a restart, `show` pops from `after_restart`."""

    def __init__(self) -> None:
        self.units: Dict[str, Dict[str, str]] = {}
        self.after_restart: Dict[str, List[Dict[str, str]]] = {}
        self.restarted: Dict[str, bool] = {}
        self.calls: List[List[str]] = []
        self.fail_show: set = set()
        self.on_show: Optional[Callable[[str], None]] = None

    def run(self, argv: List[str], timeout: float) -> Tuple[int, bytes]:
        self.calls.append(list(argv))
        assert argv[0] == "systemctl", argv
        if argv[1] == "show":
            props, unit = argv[3].split(","), argv[4]
            if self.on_show:
                self.on_show(unit)
            if unit in self.fail_show:
                return 1, b""
            if unit not in self.units:   # systemd prints defaults for a missing unit, rc 0
                cur = {"ActiveState": "inactive", "LoadState": "not-found", "SubState": "dead"}
            elif self.restarted.get(unit) and self.after_restart.get(unit):
                q = self.after_restart[unit]
                cur = q.pop(0) if len(q) > 1 else q[0]
                self.units[unit] = cur
            else:
                cur = self.units[unit]
            return 0, "".join(f"{p}={cur.get(p, '')}\n" for p in props).encode()
        if argv[1] == "cat":
            return (0, b"[Service]\nExecStart=/x\n") if argv[2] in self.units else (1, b"")
        if argv[1] == "restart":
            assert argv[2] == "--no-block"
            self.restarted[argv[3]] = True
            return 0, b""
        raise AssertionError(argv)

    def restart_calls(self) -> List[List[str]]:
        return [c for c in self.calls if c[1] == "restart"]


class FakeProbe:
    """Per-port script: a value (int or exception) or a list consumed one per call (last sticks)."""

    def __init__(self) -> None:
        self.by_port: Dict[int, Any] = {3000: 200, 11434: 200, 80: 404}
        self.calls: List[Tuple[str, int, str, float]] = []

    def __call__(self, host: str, port: int, path: str, timeout: float) -> int:
        self.calls.append((host, port, path, timeout))
        v = self.by_port[port]
        if isinstance(v, list):
            v = v.pop(0) if len(v) > 1 else v[0]
        if isinstance(v, BaseException) or (isinstance(v, type) and issubclass(v, BaseException)):
            raise v
        return v


class FakeUrlopen:
    def __init__(self) -> None:
        self.requests: List[Any] = []
        self.fail: Optional[BaseException] = None

    def __call__(self, req: Any, timeout: float = 0) -> Any:
        self.requests.append(req)
        if self.fail is not None:
            raise self.fail

        class R:
            def close(self) -> None:
                pass
        return R()


HEAL_CONF = """[heal]
dry_run = {dry}
interval_s = 60
strikes = 2
probe_timeout_s = 5
min_active_s = 180
min_uptime_s = 300
busy_max_age_s = 1800
hold_units = sentinel-ops.service
cap_hour = 3
cap_day = 6
poll_s = 2
restart_timeout_grace_s = 10
log_path = {d}/log/heal.jsonl
status_path = {d}/lib/status.json
run_dir = {d}/run
notify_conf = {d}/etc/notify.conf
notify_repeat_s = 3600

[target:sentinel-agent]
unit = sentinel-agent.service
probe = http://127.0.0.1:3000/health
post_restart_wait_s = 15
requires_iface = tailscale0
busy_marker = {d}/sentinel/busy

[target:ollama]
unit = ollama.service
probe = http://127.0.0.1:11434/api/version
post_restart_wait_s = 15,45

[target:nginx]
unit = nginx.service
probe = http://127.0.0.1:80/
post_restart_wait_s = 15
"""


@dataclass
class FakeDeps:
    root: str
    deps: sh.Deps
    sysd: FakeSystemd
    clock: FakeClock
    probe: FakeProbe
    url: FakeUrlopen
    logs: List[str] = field(default_factory=list)
    fsyncs: List[int] = field(default_factory=list)
    iface: Dict[str, Optional[str]] = field(default_factory=dict)

    @property
    def log_path(self) -> str:
        return os.path.join(self.root, "log", "heal.jsonl")

    def write_conf(self, dry: int = 0, text: Optional[str] = None) -> None:
        with open(self.deps.paths.conf, "w") as f:
            f.write(text if text is not None else HEAL_CONF.format(dry=dry, d=self.root))
        os.chmod(self.deps.paths.conf, 0o644)

    def write_notify(self, url: str = "https://ntfy.example.invalid/secret-topic", token: str = "") -> None:
        p = os.path.join(self.root, "etc", "notify.conf")
        with open(p, "w") as f:
            f.write(f"NTFY_URL={url}\nNTFY_TOKEN={token}\n")
        os.chmod(p, 0o600)

    def cfg(self) -> sh.HealConf:
        return sh.load_config(self.deps.paths.conf)

    def runner(self) -> sh.Runner:
        r = sh.Runner(self.cfg(), self.deps)
        r.uptime = self.deps.uptime()
        r.held = r.check_held()
        return r

    def run(self, advance: float = 0.0) -> int:
        """One timer tick: advance the clock, then `--run`."""
        self.clock.advance(advance)
        return sh.cmd_run(self.deps)

    def rows(self) -> List[Dict[str, Any]]:
        try:
            with open(self.log_path) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def unit_rows(self, unit: str) -> List[Dict[str, Any]]:
        return [r for r in self.rows() if r["unit"] == unit]

    def state(self) -> Dict[str, Any]:
        with open(os.path.join(self.root, "run", "state.json")) as f:
            return json.load(f)


@pytest.fixture
def fd(tmp_path: Any) -> FakeDeps:
    root = str(tmp_path)
    for sub in ("log", "lib", "run", "etc", "sentinel"):
        os.makedirs(os.path.join(root, sub))
    sysd, clock, probe, url = FakeSystemd(), FakeClock(), FakeProbe(), FakeUrlopen()
    for u, pid in (("sentinel-agent.service", 100), ("ollama.service", 200), ("nginx.service", 300)):
        sysd.units[u] = unit_props(MainPID=pid, InvocationID="inv-" + u.split(".")[0])
    sysd.units["nginx.service"]["TimeoutStopUSec"] = "5s"
    holder: Dict[str, Any] = {}
    iface: Dict[str, Optional[str]] = {"tailscale0": "100.64.0.1"}
    logs: List[str] = []
    fsyncs: List[int] = []
    deps = sh.Deps(run_cmd=sysd.run, probe_fn=probe,
                   clock=sh.Clock(time=clock.time, monotonic=clock.monotonic, sleep=clock.sleep),
                   urlopen=url, paths=sh.Paths(conf=os.path.join(root, "etc", "heal.conf"),
                                               etc_dir=os.path.join(root, "etc")),
                   syslog=logs.append, fsync=fsyncs.append, uptime=lambda: 86400.0,
                   iface_addr=lambda n: iface.get(n), environ={"INVOCATION_ID": "run1"})
    f = FakeDeps(root, deps, sysd, clock, probe, url, logs, fsyncs, iface)
    holder["fd"] = f
    f.write_conf(dry=0)
    return f
