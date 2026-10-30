#!/usr/bin/env python3
"""sentinel-heal: loopback probe timer that restarts hung (alive-but-not-serving) units.

Design: SENTINEL_HEAL_DESIGN_2026-10-29.md. Python 3.10, stdlib only, runs as root.
Subcommands: --run, --alert-unit UNIT, --selftest, --status.
All side effects go through Deps so tests need no root and no network.
"""
from __future__ import annotations

import argparse
import calendar
import configparser
import errno
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import time as _time_mod  # Clock.time would shadow the module in its class body
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

ETC_DIR = "/etc/sentinel-heal"
CONF_PATH = ETC_DIR + "/heal.conf"
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SELF_UNIT = "sentinel-heal.service"
SCHEMA_V = 1
OUTCOMES = frozenset({"VERIFIED", "FAILED", "TIMEOUT", "SKIPPED", "UNKNOWN", "CAPPED", "DRY_RUN",
                      "DOWN1", "RECOVERED", "EXTERNAL_RESTART", "HEAL_ERROR"})
PROBES = frozenset({"OK", "DOWN", "UNKNOWN", "-"})
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:\\-]{0,90}\.service$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
WORD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
SHOW_PROPS = ["ActiveState", "SubState", "Result", "Job", "MainPID", "InvocationID", "NRestarts",
              "ActiveEnterTimestampMonotonic", "TimeoutStopUSec", "TimeoutStartUSec"]
ALERT_PROPS = ["ActiveState", "Result", "NRestarts", "ExecMainStatus"]
HELD_STATES = frozenset({"active", "activating", "deactivating", "reloading"})
NEVER_SUPPRESS = frozenset({"restart_verified", "restart_failed"})
HIGH_PRIORITY = frozenset({"restart_failed", "capped", "heal_failed", "unit_failed", "start_limit_hit"})
UNKNOWN_PERSIST_S = 1800
DEFAULT_PHASE_TIMEOUT_S = 90.0   # used when systemd reports infinity/unparseable
MAX_RESTART_WAIT_S = 480.0       # keeps the run inside the unit's TimeoutStartSec=600
MAX_POST_WAIT_S = 90             # sum of post_restart_wait_s; 480 + 90 + probe timeouts < 600
STATUS_MAX = 8192
SAFE_READ_MAX = 65536
UNAVAILABLE: Dict[str, Any] = {"heal": "unavailable"}
ROW_REQUIRED = ("v", "ts", "run_id", "unit", "probe", "probe_reason", "action", "outcome", "strikes",
                "old_pid", "new_pid", "old_inv", "new_inv", "nrestarts", "unit_sha256", "dry_run", "dur_ms")
ROW_OPTIONAL = ("job_pending", "caps", "notified", "would_restart")

HEAL_DEFAULTS: Dict[str, str] = {
    "dry_run": "1", "interval_s": "60", "strikes": "2", "probe_timeout_s": "5", "min_active_s": "180",
    "min_uptime_s": "300", "busy_max_age_s": "1800", "hold_units": "sentinel-ops.service",
    "cap_hour": "3", "cap_day": "6", "poll_s": "2", "restart_timeout_grace_s": "10",
    "log_path": "/var/log/sentinel-heal/heal.jsonl", "status_path": "/var/lib/sentinel-heal/status.json",
    "run_dir": "/run/sentinel-heal", "notify_conf": ETC_DIR + "/notify.conf", "notify_repeat_s": "3600"}
TARGET_KEYS = frozenset({"unit", "probe", "post_restart_wait_s", "requires_iface", "busy_marker"})


class ConfigError(Exception):
    """heal.conf is invalid. Messages never contain notify.conf values."""


# ---------------------------------------------------------------- deps

def default_run_cmd(argv: List[str], timeout: float) -> Tuple[int, bytes]:
    """Run argv (no shell) with a fixed PATH; return (rc, stdout)."""
    exe = shutil.which(argv[0], path=SAFE_PATH)
    if exe is None:
        raise FileNotFoundError(argv[0])
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": ""}
    p = subprocess.run([exe] + argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=timeout, env=env, check=False)
    return p.returncode, p.stdout


def http_status(host: str, port: int, path: str, timeout: float) -> int:
    """GET path, return the status code; the body is never read."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": "127.0.0.1", "Connection": "close",
                                            "User-Agent": "sentinel-heal"})
        return conn.getresponse().status
    finally:
        conn.close()


def default_syslog(msg: str) -> None:
    try:
        import syslog
        syslog.openlog("sentinel-heal", 0, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_INFO, msg)
    except ImportError:  # non-POSIX dev box
        print("sentinel-heal: " + msg, file=sys.stderr)


def iface_ipv4(iface: str) -> Optional[str]:
    """Primary IPv4 of iface via SIOCGIFADDR on an AF_INET socket (no netlink, no subprocess)."""
    # PLAN_GAP (13.2): design defaults to `ip -4 -o addr show dev X`, but `ip` needs AF_NETLINK,
    # which sentinel-heal.service's RestrictAddressFamilies= forbids. Implemented as an ioctl.
    import fcntl
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface.encode("ascii")[:15]))
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        s.close()


def read_uptime() -> float:
    with open("/proc/uptime", encoding="ascii") as f:
        return float(f.read().split()[0])


@dataclass
class Clock:
    time: Callable[[], float] = _time_mod.time
    monotonic: Callable[[], float] = _time_mod.monotonic
    sleep: Callable[[float], None] = _time_mod.sleep


@dataclass
class Paths:
    conf: str = CONF_PATH
    etc_dir: str = ETC_DIR


@dataclass
class Deps:
    run_cmd: Callable[[List[str], float], Tuple[int, bytes]] = default_run_cmd
    probe_fn: Callable[[str, int, str, float], int] = http_status
    clock: Clock = field(default_factory=Clock)
    urlopen: Callable[..., Any] = urllib.request.urlopen
    paths: Paths = field(default_factory=Paths)
    syslog: Callable[[str], None] = default_syslog
    fsync: Callable[[int], None] = os.fsync
    uptime: Callable[[], float] = read_uptime
    iface_addr: Callable[[str], Optional[str]] = iface_ipv4
    stat: Callable[[str], os.stat_result] = os.stat
    environ: Dict[str, str] = field(default_factory=lambda: dict(os.environ))


# ---------------------------------------------------------------- config

@dataclass
class Target:
    name: str
    unit: str
    host: str
    port: int
    path: str
    post_restart_wait_s: List[int]
    requires_iface: str = ""
    busy_marker: str = ""


@dataclass
class HealConf:
    dry_run: bool = True
    interval_s: int = 60
    strikes: int = 2
    probe_timeout_s: int = 5
    min_active_s: int = 180
    min_uptime_s: int = 300
    busy_max_age_s: int = 1800
    hold_units: List[str] = field(default_factory=lambda: ["sentinel-ops.service"])
    cap_hour: int = 3
    cap_day: int = 6
    poll_s: int = 2
    restart_timeout_grace_s: int = 10
    log_path: str = HEAL_DEFAULTS["log_path"]
    status_path: str = HEAL_DEFAULTS["status_path"]
    run_dir: str = HEAL_DEFAULTS["run_dir"]
    notify_conf: str = HEAL_DEFAULTS["notify_conf"]
    notify_repeat_s: int = 3600
    targets: List[Target] = field(default_factory=list)

    @property
    def min_strike_gap_s(self) -> int:
        return self.interval_s - 10


def _int(key: str, raw: str, lo: int, hi: int) -> int:
    try:
        v = int(raw.strip())
    except ValueError:
        raise ConfigError(f"{key}: not an integer") from None
    if not lo <= v <= hi:
        raise ConfigError(f"{key}: must be in [{lo},{hi}]")
    return v


def _abs_path(key: str, raw: str) -> str:
    v = raw.strip()
    if not v.startswith("/") or "\x00" in v or ".." in v.split("/"):
        raise ConfigError(f"{key}: must be an absolute path")
    return v


def parse_probe(name: str, url: str) -> Tuple[str, int, str]:
    """Return (host, port, path). Only http://127.0.0.1 is accepted; localhost is rejected."""
    sp = urllib.parse.urlsplit(url.strip())
    host = sp.netloc.rsplit("@", 1)[-1].split(":", 1)[0]
    if sp.scheme != "http":
        raise ConfigError(f"target:{name} probe: scheme must be http")
    if host != "127.0.0.1":
        raise ConfigError(f"target:{name} probe: host must be the literal 127.0.0.1 (localhost rejected)")
    if "@" in sp.netloc or sp.fragment:
        raise ConfigError(f"target:{name} probe: userinfo/fragment not allowed")
    try:
        port = sp.port or 80
    except ValueError:
        raise ConfigError(f"target:{name} probe: bad port") from None
    path = (sp.path or "/") + ("?" + sp.query if sp.query else "")
    if not path.startswith("/") or any(c.isspace() or ord(c) < 32 for c in path):
        raise ConfigError(f"target:{name} probe: bad path")
    return host, port, path


def parse_waits(name: str, raw: str) -> List[int]:
    """'15' or '15,45': sequential sleeps (§5.2 `for wait in ...: sleep(wait)`), 15 then 45 more.
    Total bounded so restart budget (<= MAX_RESTART_WAIT_S) + waits + probes fits TimeoutStartSec=600."""
    out = [_int(f"target:{name} post_restart_wait_s", p, 1, 90) for p in raw.split(",")]
    if sum(out) > MAX_POST_WAIT_S:
        raise ConfigError(f"target:{name} post_restart_wait_s: total must be <= {MAX_POST_WAIT_S}")
    return out


def load_config(path: str) -> HealConf:
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError("heal.conf: not a regular file")
    if st.st_mode & 0o022:
        raise ConfigError("heal.conf: group/other writable")
    if not st.st_mode & 0o400:   # root ignores DAC; honour an operator's chmod 000 (gate G9)
        raise ConfigError("heal.conf: not owner-readable")
    if hasattr(os, "geteuid") and st.st_uid not in (0, os.geteuid()):
        raise ConfigError("heal.conf: not owned by root")
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",),
                                   comment_prefixes=("#", ";"), strict=True)
    try:
        with open(path, encoding="utf-8") as f:
            cp.read_file(f)
    except configparser.Error as e:
        raise ConfigError("heal.conf: parse error: " + type(e).__name__) from None
    if cp.defaults():
        raise ConfigError("heal.conf: [DEFAULT] section not allowed")
    if "heal" not in cp:
        raise ConfigError("heal.conf: missing [heal]")
    h = cp["heal"]
    unknown = set(h.keys()) - set(HEAL_DEFAULTS)
    if unknown:
        raise ConfigError("heal.conf [heal]: unknown key(s): " + ",".join(sorted(unknown)))
    v = {k: h.get(k, d) for k, d in HEAL_DEFAULTS.items()}
    cfg = HealConf(
        dry_run=bool(_int("dry_run", v["dry_run"], 0, 1)),
        interval_s=_int("interval_s", v["interval_s"], 20, 3600),
        strikes=_int("strikes", v["strikes"], 1, 10),
        probe_timeout_s=_int("probe_timeout_s", v["probe_timeout_s"], 1, 30),
        min_active_s=_int("min_active_s", v["min_active_s"], 0, 86400),
        min_uptime_s=_int("min_uptime_s", v["min_uptime_s"], 0, 86400),
        busy_max_age_s=_int("busy_max_age_s", v["busy_max_age_s"], 0, 86400),
        hold_units=[u for u in re.split(r"[\s,]+", v["hold_units"].strip()) if u],
        cap_hour=_int("cap_hour", v["cap_hour"], 0, 100),
        cap_day=_int("cap_day", v["cap_day"], 0, 1000),
        poll_s=_int("poll_s", v["poll_s"], 1, 60),
        restart_timeout_grace_s=_int("restart_timeout_grace_s", v["restart_timeout_grace_s"], 0, 300),
        log_path=_abs_path("log_path", v["log_path"]),
        status_path=_abs_path("status_path", v["status_path"]),
        run_dir=_abs_path("run_dir", v["run_dir"]),
        notify_conf=_abs_path("notify_conf", v["notify_conf"]),
        notify_repeat_s=_int("notify_repeat_s", v["notify_repeat_s"], 0, 604800))
    for u in cfg.hold_units:
        if not UNIT_RE.match(u):
            raise ConfigError("hold_units: bad unit name")
    for sec in cp.sections():
        if sec == "heal":
            continue
        if not sec.startswith("target:") or not NAME_RE.match(sec[7:]):
            raise ConfigError("heal.conf: unknown section [" + sec[:40] + "]")
        name, s = sec[7:], cp[sec]
        bad = set(s.keys()) - TARGET_KEYS
        if bad:
            raise ConfigError(f"target:{name}: unknown key(s): " + ",".join(sorted(bad)))
        unit = s.get("unit", "").strip()
        if not UNIT_RE.match(unit):
            raise ConfigError(f"target:{name}: unit missing or invalid")
        if "probe" not in s:
            raise ConfigError(f"target:{name}: probe missing")
        host, port, ppath = parse_probe(name, s["probe"])
        iface = s.get("requires_iface", "").strip()
        if iface and not IFACE_RE.match(iface):
            raise ConfigError(f"target:{name}: bad requires_iface")
        busy = s.get("busy_marker", "").strip()
        cfg.targets.append(Target(name, unit, host, port, ppath, parse_waits(name, s.get("post_restart_wait_s", "15")),
                                  iface, _abs_path(f"target:{name} busy_marker", busy) if busy else ""))
    if not cfg.targets:
        raise ConfigError("heal.conf: no [target:*] sections")
    return cfg


def load_notify(path: str) -> Optional[Tuple[str, str]]:
    """Return (url, token) or None (absent/empty = log-only). Never raises, never logs values."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    kv: Dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, val = line.split("=", 1)
        val = val.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if val.startswith("#"):
            val = ""
        kv[k.strip()] = val
    url = kv.get("NTFY_URL", "")
    if not url.startswith(("https://", "http://")):
        return None
    return url, kv.get("NTFY_TOKEN", "")


# ---------------------------------------------------------------- probe classification (§6)

def _errname(e: OSError) -> str:
    return "errno:" + errno.errorcode.get(e.errno or 0, "unknown")


def classify(probe_fn: Callable[[str, int, str, float], int], host: str, port: int,
             path: str, timeout: float) -> Tuple[str, str]:
    """Return (OK|DOWN|UNKNOWN, reason) per the §6 table."""
    try:
        code = probe_fn(host, port, path, timeout)
    except ConnectionRefusedError:
        return "DOWN", "econnrefused"
    except (ConnectionResetError, http.client.RemoteDisconnected):
        return "DOWN", "econnreset"
    except (socket.timeout, TimeoutError):
        return "DOWN", "timeout"
    except PermissionError:
        return "UNKNOWN", "eperm"
    except socket.gaierror:
        return "UNKNOWN", "dns"
    except OSError as e:
        return "UNKNOWN", _errname(e)
    except http.client.HTTPException:
        return "UNKNOWN", "http-garbage"
    except Exception as e:  # anything unexpected must never restart
        return "UNKNOWN", "error:" + type(e).__name__[:40]
    if isinstance(code, int) and 100 <= code <= 499:
        return "OK", f"http:{code}"
    if isinstance(code, int) and 500 <= code <= 599:
        return "DOWN", f"http:{code}"
    return "UNKNOWN", "http-garbage"


# ---------------------------------------------------------------- files

def utc_ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def parse_ts(s: Any) -> Optional[float]:
    if not isinstance(s, str) or not TS_RE.match(s):
        return None
    return float(calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))


def load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write(path: str, data: bytes, mode: int, fsync: Callable[[int], None]) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.write(fd, data)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def append_row(path: str, row: Dict[str, Any], fsync: Callable[[int], None]) -> None:
    line = json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o640)
    try:
        os.write(fd, line.encode("ascii"))
        fsync(fd)
    finally:
        os.close(fd)


def read_rows(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict):
                    rows.append(r)
    except OSError:
        pass
    return rows


def count_actions(rows: List[Dict[str, Any]], unit: str, now: float,
                  dry_run: bool = False) -> Tuple[int, int]:
    """Restart attempts for unit in the last 3600 s / 86400 s: rows with action=="restart" (any
    outcome). In dry-run mode, would-be restarts (action=="dry_run_restart") count too, so caps
    behave as they would live; they never count in live mode, and CAPPED rows (action "none")
    never count, so a long outage cannot keep the cap refreshed forever (sol H-03)."""
    counted = ("restart", "dry_run_restart") if dry_run else ("restart",)
    hour = day = 0
    for r in rows:
        if r.get("unit") != unit or r.get("action") not in counted:
            continue
        t = parse_ts(r.get("ts"))
        if t is None:
            continue
        age = now - t
        if age < 86400:   # future-dated rows (clock step back) count: safer to over-count
            day += 1
            if age < 3600:
                hour += 1
    return hour, day


_SPAN_UNITS = {"us": 1e-6, "\u00b5s": 1e-6, "ms": 1e-3, "s": 1.0, "min": 60.0, "h": 3600.0,
               "d": 86400.0, "w": 604800.0, "M": 2629800.0, "y": 31557600.0}
_SPAN_TOK = re.compile(r"(\d+(?:\.\d+)?)\s*(us|\u00b5s|ms|min|s|h|d|w|M|y)")


def parse_timespan(raw: str) -> Optional[float]:
    """systemd timespan ('1min 30s', '5s', '100ms', raw usec) -> seconds; None for infinity/garbage."""
    s = raw.strip()
    if s.isdigit():
        return int(s) / 1e6
    if not s or not re.fullmatch(r"(?:\s*\d+(?:\.\d+)?\s*(?:us|\u00b5s|ms|min|s|h|d|w|M|y)\s*)+", s):
        return None
    return sum(float(n) * _SPAN_UNITS[u] for n, u in _SPAN_TOK.findall(s))


def _word(s: str) -> str:
    """systemd state words only; anything else is replaced so no foreign text enters a row."""
    return s if WORD_RE.match(s) else "other"


def _pint(s: Any) -> int:
    try:
        return int(str(s).strip())
    except ValueError:
        return 0


# ---------------------------------------------------------------- the run

class Runner:
    def __init__(self, cfg: HealConf, deps: Deps, read_log: bool = True) -> None:
        self.cfg, self.d = cfg, deps
        self.run_id = _word(deps.environ.get("INVOCATION_ID", "") or "manual")
        self.rows: List[Dict[str, Any]] = read_rows(cfg.log_path) if read_log else []
        self.notify_cfg = load_notify(cfg.notify_conf)
        # Live restarts require a working alert channel (sol H-05): without notify.conf, heal
        # behaves exactly as dry_run = 1 (rows say dry_run true) and says so once in syslog.
        self.dry = cfg.dry_run or self.notify_cfg is None
        self.live_blocked = not cfg.dry_run and self.notify_cfg is None
        self.nstate_path = os.path.join(cfg.run_dir, "notify.json")
        self.nstate = load_json(self.nstate_path)
        self.state_path = os.path.join(cfg.run_dir, "state.json")
        self.state: Dict[str, Dict[str, Any]] = load_json(self.state_path)
        etc = deps.paths.etc_dir
        self.paused = os.path.exists(os.path.join(etc, "pause")) or os.path.exists(os.path.join(cfg.run_dir, "pause"))
        self.killed = os.path.exists(os.path.join(etc, "KILL"))
        self.held: Optional[str] = None
        self.uptime = 0.0

    # -- systemd helpers
    def cmd(self, argv: List[str], timeout: float = 30.0) -> Tuple[int, bytes]:
        try:
            return self.d.run_cmd(argv, timeout)
        except Exception:
            return -1, b""

    def show(self, unit: str, props: List[str]) -> Optional[Dict[str, str]]:
        rc, out = self.cmd(["systemctl", "show", "-p", ",".join(props), unit])
        if rc != 0:
            return None
        res = {p: "" for p in props}
        for line in out.decode("utf-8", "replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k in res:
                    res[k] = v.strip()
        return res

    def unit_sha(self, unit: str) -> str:
        rc, out = self.cmd(["systemctl", "cat", unit])
        return hashlib.sha256(out).hexdigest() if rc == 0 else ""

    def check_held(self) -> Optional[str]:
        """First hold unit that is active/activating/deactivating/reloading. Missing unit = not held;
        a failed systemctl call counts as held (no restart while we cannot see the broker)."""
        for h in self.cfg.hold_units:
            u = self.show(h, ["ActiveState"])
            if u is None or u["ActiveState"] in HELD_STATES:
                return h
        return None

    def iface_ok(self, iface: str) -> bool:
        try:
            addr = self.d.iface_addr(iface)
        except Exception:
            return False
        return isinstance(addr, str) and addr.startswith("100.")

    def busy(self, marker: str) -> bool:
        try:
            mtime = os.lstat(marker).st_mtime   # mtime only; content never read
        except OSError:
            return False
        return self.d.clock.time() - mtime < self.cfg.busy_max_age_s

    # -- recording
    def emit(self, unit: str, st: Dict[str, Any], outcome: str, t0: float, **kw: Any) -> Dict[str, Any]:
        now = self.d.clock.time()
        row: Dict[str, Any] = {
            "v": SCHEMA_V, "ts": utc_ts(now), "run_id": self.run_id, "unit": unit,
            "probe": kw.pop("probe", "-"), "probe_reason": str(kw.pop("probe_reason", ""))[:64],
            "action": kw.pop("action", "none"), "outcome": outcome, "strikes": int(st.get("strikes", 0)),
            "old_pid": kw.pop("old_pid", 0), "new_pid": kw.pop("new_pid", 0),
            "old_inv": kw.pop("old_inv", ""), "new_inv": kw.pop("new_inv", ""),
            "nrestarts": kw.pop("nrestarts", 0), "unit_sha256": kw.pop("unit_sha256", ""),
            "dry_run": self.dry, "dur_ms": int(max(0.0, self.d.clock.monotonic() - t0) * 1000)}
        for k in ROW_OPTIONAL:
            if k in kw:
                row[k] = kw.pop(k)
        st["last_outcome"], st["last_reason"] = outcome, row["probe_reason"]
        if row["action"] == "restart":
            st["last_action_ts"] = row["ts"]
        try:
            append_row(self.cfg.log_path, row, self.d.fsync)
        finally:
            self.rows.append(row)
            self.d.syslog(f"{unit} {outcome} action={row['action']} probe={row['probe']} "
                          f"reason={row['probe_reason']} strikes={row['strikes']} dry_run={int(self.dry)}")
        return row

    def notify(self, event: str, unit: str, outcome: str, reason: str) -> bool:
        if self.notify_cfg is None:
            if not self.nstate.get("_disabled_logged"):
                self.d.syslog("notify: disabled, " + self.cfg.notify_conf + " absent")
                self.nstate["_disabled_logged"] = 1
                self._save_nstate()
            return False
        now = self.d.clock.time()
        key = f"{unit}|{event}"
        last = self.nstate.get(key, 0)
        if event not in NEVER_SUPPRESS and isinstance(last, (int, float)) and now - last < self.cfg.notify_repeat_s:
            return False
        url, token = self.notify_cfg
        headers = {"Title": "sentinel-heal " + event, "Priority": "4" if event in HIGH_PRIORITY else "3"}
        if token:
            headers["Authorization"] = "Bearer " + token
        body = f"[sentinel-heal] {event} {unit} {outcome} {reason}".encode("ascii", "replace")
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            resp = self.d.urlopen(req, timeout=10)
            close = getattr(resp, "close", None)
            if callable(close):
                close()
        except Exception as e:  # never str(e): it may carry the URL
            self.emit(SELF_UNIT, {}, "UNKNOWN", self.d.clock.monotonic(),
                      probe_reason="notify-failed:" + type(e).__name__[:40])
            return False
        self.nstate[key] = now
        self._save_nstate()
        return True

    def _save_nstate(self) -> None:
        try:  # best effort: heal-alert@ runs with /run read-only
            atomic_write(self.nstate_path, json.dumps(self.nstate).encode(), 0o640, self.d.fsync)
        except OSError:
            pass

    def quiet(self, t: Target, st: Dict[str, Any], u: Dict[str, str], sha: str, t0: float,
              outcome: str, reason: str, **kw: Any) -> None:
        """skip()/unknown(): row only when the reason changed."""
        if reason != st.get("last_reason"):
            self.emit(t.unit, st, outcome, t0, probe_reason=reason, new_pid=_pint(u["MainPID"]),
                      new_inv=u["InvocationID"], nrestarts=_pint(u["NRestarts"]), unit_sha256=sha, **kw)
        st["last_reason"] = reason

    def hold_reason(self, h: str) -> str:
        return "hold:" + (h[:-8] if h.endswith(".service") else h)

    # -- §5.2
    def handle(self, t: Target) -> None:
        t0 = self.d.clock.monotonic()
        st = self.state.setdefault(t.unit, {"strikes": 0})
        st["probe"] = "-"
        u = self.show(t.unit, SHOW_PROPS)
        if u is None:
            if st.get("last_reason") != "systemctl-show-failed":
                self.emit(t.unit, st, "UNKNOWN", t0, probe_reason="systemctl-show-failed")
            return None
        sha = self.unit_sha(t.unit)
        active, inv, pid = _word(u["ActiveState"]), u["InvocationID"], _pint(u["MainPID"])
        common = {"new_pid": pid, "new_inv": inv, "nrestarts": _pint(u["NRestarts"]), "unit_sha256": sha}
        last_inv = st.get("last_inv")
        if last_inv and inv != last_inv:
            if active == "active":
                own_ts = st.pop("own_restart_pending", 0)   # heal's own TIMEOUT restart finishing later
                own = isinstance(own_ts, (int, float)) and self.d.clock.time() - own_ts < 2 * MAX_RESTART_WAIT_S
                st["strikes"] = 0
                if not own:
                    self.emit(t.unit, st, "EXTERNAL_RESTART", t0, probe_reason="invocation-changed",
                              old_pid=_pint(st.get("last_pid", 0)), old_inv=str(last_inv), **common)
        if active != "activating":
            # while activating (e.g. mid restart-self) keep the old invocation so the change is
            # still seen, and EXTERNAL_RESTART logged, once the unit reaches active
            st["last_inv"], st["last_pid"] = inv, pid

        if self.paused:
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "paused")
        if self.held:
            st["strikes"] = 0
            return self.quiet(t, st, u, sha, t0, "SKIPPED", self.hold_reason(self.held))
        if self.uptime < self.cfg.min_uptime_s:
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "boot-grace")
        if u["Result"] == "start-limit-hit":
            n = self.notify("start_limit_hit", t.unit, "SKIPPED", "start-limit-hit")
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "start-limit-hit", notified=n)
        if active != "active":
            return self.quiet(t, st, u, sha, t0, "SKIPPED", f"not-active:{active}/{_word(u['SubState'])}")
        if u["Job"]:
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "pending-job:" + _word(u["Job"]))
        enter_us = _pint(u["ActiveEnterTimestampMonotonic"])
        if self.d.clock.monotonic() * 1e6 - enter_us < self.cfg.min_active_s * 1e6:
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "recently-started")
        if t.requires_iface and not self.iface_ok(t.requires_iface):
            return self.quiet(t, st, u, sha, t0, "SKIPPED", "iface-down:" + t.requires_iface)
        if t.busy_marker and self.busy(t.busy_marker):
            return self.quiet(t, st, u, sha, t0, "UNKNOWN", "busy")

        cls, reason = classify(self.d.probe_fn, t.host, t.port, t.path, self.cfg.probe_timeout_s)
        st["probe"] = cls
        now = self.d.clock.time()
        if cls == "UNKNOWN":
            if st.get("unknown_reason") != reason:
                st["unknown_reason"], st["unknown_since"] = reason, now
            elif now - float(st.get("unknown_since", now)) > UNKNOWN_PERSIST_S:
                self.notify("unknown_persistent", t.unit, "UNKNOWN", reason)
            return self.quiet(t, st, u, sha, t0, "UNKNOWN", reason, probe="UNKNOWN")
        st.pop("unknown_reason", None)
        st.pop("unknown_since", None)
        if cls == "OK":
            st.pop("capped", None)
            if st.get("strikes", 0) > 0:
                st["strikes"] = 0
                self.emit(t.unit, st, "RECOVERED", t0, probe="OK", probe_reason=reason, **common)
            st["strikes"] = 0
            st["last_reason"] = ""
            return None
        # DOWN
        strikes = int(st.get("strikes", 0))
        down_since = float(st.get("down_since", 0))
        if strikes == 0 or now - down_since > 3 * self.cfg.interval_s:
            st["strikes"], st["down_since"] = 1, now
            self.emit(t.unit, st, "DOWN1", t0, probe="DOWN", probe_reason=reason, **common)
            return None
        if now - down_since < self.cfg.min_strike_gap_s:
            return None
        st["strikes"] = strikes + 1
        if st["strikes"] < self.cfg.strikes:
            self.emit(t.unit, st, "DOWN" + str(st["strikes"]), t0, probe="DOWN", probe_reason=reason, **common)
            return None
        return self.act(t, st, u, sha, t0, reason, common)

    def act(self, t: Target, st: Dict[str, Any], u: Dict[str, str], sha: str, t0: float,
            reason: str, common: Dict[str, Any]) -> None:
        nh, nd = count_actions(self.rows, t.unit, self.d.clock.time(), self.dry)
        caps = {"hour": nh, "day": nd}
        if nh >= self.cfg.cap_hour or nd >= self.cfg.cap_day:
            st["strikes"] = 0
            if st.get("capped"):          # one CAPPED row per capped spell, not one per strike pair
                return None
            st["capped"] = True
            n = self.notify("capped", t.unit, "CAPPED", reason)
            self.emit(t.unit, st, "CAPPED", t0, probe="DOWN", probe_reason=reason, action="none",
                      caps=caps, notified=n, would_restart=True, **common)
            return None
        st.pop("capped", None)
        held = self.check_held()   # re-check right before acting (DRY_RUN mirrors live)
        if held:
            st["strikes"] = 0
            return self.quiet(t, st, u, sha, t0, "SKIPPED", self.hold_reason(held))
        if self.dry:
            st["strikes"] = 0
            if self.live_blocked and not self.nstate.get("_live_blocked_logged"):
                self.d.syslog("live restarts BLOCKED: dry_run = 0 but " + self.cfg.notify_conf +
                              " is absent; acting as dry run")
                self.nstate["_live_blocked_logged"] = 1
                self._save_nstate()
            n = self.notify("dry_run_restart", t.unit, "DRY_RUN", reason)
            self.emit(t.unit, st, "DRY_RUN", t0, probe="DOWN", probe_reason=reason,
                      action="dry_run_restart", caps=caps, notified=n, would_restart=True, **common)
            return None
        b_pid, b_inv = _pint(u["MainPID"]), u["InvocationID"]
        phases = [parse_timespan(u["TimeoutStopUSec"]), parse_timespan(u["TimeoutStartUSec"])]
        budget = sum(DEFAULT_PHASE_TIMEOUT_S if p is None else p for p in phases) + self.cfg.restart_timeout_grace_s
        deadline = self.d.clock.monotonic() + min(budget, MAX_RESTART_WAIT_S)
        st["strikes"] = 0
        base = {"probe": "DOWN", "action": "restart", "caps": caps, "old_pid": b_pid, "old_inv": b_inv,
                "unit_sha256": sha}
        rc, _ = self.cmd(["systemctl", "restart", "--no-block", t.unit])
        if rc != 0:
            n = self.notify("restart_failed", t.unit, "FAILED", f"restart-cmd-rc:{rc}")
            self.emit(t.unit, st, "FAILED", t0, probe_reason=f"restart-cmd-rc:{rc}", notified=n, **base)
            return None
        u2: Optional[Dict[str, str]] = None
        while self.d.clock.monotonic() < deadline:
            self.d.clock.sleep(self.cfg.poll_s)
            u2 = self.show(t.unit, SHOW_PROPS)
            if u2 is not None and u2["Job"] == "":
                break
        else:
            st["own_restart_pending"] = self.d.clock.time()
            n = self.notify("restart_failed", t.unit, "TIMEOUT", "job-pending")
            self.emit(t.unit, st, "TIMEOUT", t0, probe_reason="job-pending", job_pending=True, notified=n, **base)
            return None
        assert u2 is not None
        st["last_inv"], st["last_pid"] = u2["InvocationID"], _pint(u2["MainPID"])
        after = {"new_pid": _pint(u2["MainPID"]), "new_inv": u2["InvocationID"], "nrestarts": _pint(u2["NRestarts"])}
        if u2["ActiveState"] != "active":
            why = f"post-restart:{_word(u2['ActiveState'])}/{_word(u2['Result'])}"
            n = self.notify("restart_failed", t.unit, "FAILED", why)
            self.emit(t.unit, st, "FAILED", t0, probe_reason=why, notified=n, **base, **after)
            return None
        u3, cls2, r2 = u2, "UNKNOWN", "not-probed"
        for wait in t.post_restart_wait_s:
            self.d.clock.sleep(wait)
            u3 = self.show(t.unit, SHOW_PROPS) or {"MainPID": "0", "InvocationID": "", "NRestarts": "0"}
            cls2, r2 = classify(self.d.probe_fn, t.host, t.port, t.path, self.cfg.probe_timeout_s)
            if cls2 == "OK":
                break
        a_pid = _pint(u3["MainPID"])
        ok = cls2 == "OK" and a_pid != b_pid and a_pid != 0
        outcome = "VERIFIED" if ok else "FAILED"
        if u3["InvocationID"]:
            st["last_inv"], st["last_pid"] = u3["InvocationID"], a_pid
        n = self.notify("restart_verified" if ok else "restart_failed", t.unit, outcome, r2)
        base["probe"] = cls2
        self.emit(t.unit, st, outcome, t0, probe_reason=r2, notified=n, new_pid=a_pid,
                  new_inv=u3["InvocationID"], nrestarts=_pint(u3["NRestarts"]), **base)
        return None

    def heal_error(self, unit: str, e: BaseException) -> None:
        self.d.syslog(f"HEAL_ERROR {unit} {type(e).__name__}")
        try:
            self.emit(unit, self.state.get(unit, {}) if unit != SELF_UNIT else {}, "HEAL_ERROR",
                      self.d.clock.monotonic(), probe_reason="exception:" + type(e).__name__[:40])
        except Exception:
            pass

    def save(self, ok: bool) -> None:
        atomic_write(self.state_path, json.dumps(self.state, ensure_ascii=True).encode(), 0o640, self.d.fsync)
        now = self.d.clock.time()
        units: Dict[str, Any] = {}
        for t in self.cfg.targets:
            st = self.state.get(t.unit, {})
            ext = sum(1 for r in self.rows if r.get("unit") == t.unit and r.get("outcome") == "EXTERNAL_RESTART"
                      and (parse_ts(r.get("ts")) or 0) > now - 86400)
            units[t.unit] = {"probe": st.get("probe", "-"), "strikes": int(st.get("strikes", 0)),
                             "last_outcome": st.get("last_outcome", "-"),
                             "last_action_ts": st.get("last_action_ts", ""), "external_restarts_24h": ext}
        recent = [{k: r.get(k) for k in ("ts", "unit", "action", "outcome", "probe_reason")} for r in self.rows[-5:]]
        obj = {"v": SCHEMA_V, "ts": utc_ts(now), "dry_run": self.cfg.dry_run, "paused": self.paused,
               "killed": self.killed, "last_run_ok": ok, "units": units, "recent": recent}
        data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode()
        while len(data) > STATUS_MAX and obj["recent"]:
            obj["recent"].pop(0)
            data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode()
        atomic_write(self.cfg.status_path, data, 0o644, self.d.fsync)


# ---------------------------------------------------------------- safe reader for the agent (§8.3)

def safe_read_status(path: str, require_uid: int = 0) -> Dict[str, Any]:
    """Read status.json as an unprivileged user; whitelisted, enum-validated keys only."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return dict(UNAVAILABLE)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != require_uid or st.st_size > SAFE_READ_MAX:
            return dict(UNAVAILABLE)
        buf = b""
        while len(buf) <= SAFE_READ_MAX:
            chunk = os.read(fd, SAFE_READ_MAX + 1 - len(buf))
            if not chunk:
                break
            buf += chunk
    except OSError:
        return dict(UNAVAILABLE)
    finally:
        os.close(fd)
    if len(buf) > SAFE_READ_MAX:
        return dict(UNAVAILABLE)
    try:
        obj = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return dict(UNAVAILABLE)
    if not isinstance(obj, dict):
        return dict(UNAVAILABLE)
    out: Dict[str, Any] = {}
    if isinstance(obj.get("ts"), str) and TS_RE.match(obj["ts"]):
        out["ts"] = obj["ts"]
    for k in ("dry_run", "paused", "killed", "last_run_ok"):
        if isinstance(obj.get(k), bool):
            out[k] = obj[k]
    units: Dict[str, Any] = {}
    raw_units = obj.get("units")
    if isinstance(raw_units, dict):
        for name, u in list(raw_units.items())[:16]:
            if not isinstance(name, str) or not UNIT_RE.match(name) or not isinstance(u, dict):
                continue
            clean: Dict[str, Any] = {}
            if u.get("probe") in PROBES:
                clean["probe"] = u["probe"]
            s = u.get("strikes")
            if isinstance(s, int) and not isinstance(s, bool) and 0 <= s <= 100:
                clean["strikes"] = s
            if u.get("last_outcome") in OUTCOMES:
                clean["last_outcome"] = u["last_outcome"]
            units[name] = clean
    out["units"] = units
    return out


# ---------------------------------------------------------------- subcommands

def cmd_run(deps: Deps) -> int:
    if os.path.exists(os.path.join(deps.paths.etc_dir, "KILL")):
        return 0
    try:
        cfg = load_config(deps.paths.conf)
    except Exception as e:
        cfg = HealConf()
        r = Runner(cfg, deps, read_log=False)
        r.heal_error(SELF_UNIT, e)
        print("sentinel-heal: config error: " + (str(e) if isinstance(e, ConfigError) else type(e).__name__),
              file=sys.stderr)
        return 1
    os.makedirs(cfg.run_dir, mode=0o750, exist_ok=True)
    lock_fd = os.open(os.path.join(cfg.run_dir, "lock"), os.O_RDWR | os.O_CREAT, 0o640)
    try:
        try:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            pass
        except OSError:
            deps.syslog("overlap: another run holds the lock")
            return 0
        r = Runner(cfg, deps)
        ok = True
        try:
            r.uptime = deps.uptime()
            r.held = r.check_held()
            for t in cfg.targets:
                try:
                    r.handle(t)
                except Exception as e:
                    ok = False
                    r.heal_error(t.unit, e)
        except Exception as e:
            ok = False
            r.heal_error(SELF_UNIT, e)
        try:
            r.save(ok)
        except Exception as e:
            ok = False
            r.heal_error(SELF_UNIT, e)
        return 0 if ok else 1
    finally:
        os.close(lock_fd)


def cmd_alert_unit(deps: Deps, unit: str) -> int:
    if not UNIT_RE.match(unit):
        print("sentinel-heal: invalid unit name", file=sys.stderr)
        return 2
    try:
        cfg = load_config(deps.paths.conf)
    except Exception:
        cfg = HealConf()   # must still alert when heal.conf is what broke heal
    r = Runner(cfg, deps, read_log=False)
    t0 = deps.clock.monotonic()
    u = r.show(unit, ALERT_PROPS) or {}
    result = _word(u.get("Result", "") or "unknown")
    reason = "onfailure:" + result
    event = "heal_failed" if unit == SELF_UNIT else "unit_failed"
    n = r.notify(event, unit, "SKIPPED", reason)
    r.emit(unit, {}, "SKIPPED", t0, action="alert", probe_reason=reason, nrestarts=_pint(u.get("NRestarts", 0)),
           unit_sha256=r.unit_sha(unit), notified=n)
    return 0


def cmd_selftest(deps: Deps) -> int:
    errors = 0
    try:
        cfg = load_config(deps.paths.conf)
    except (ConfigError, OSError) as e:
        print("config: ERROR " + (str(e) if isinstance(e, ConfigError) else type(e).__name__))
        return 1
    print(f"config: ok dry_run={int(cfg.dry_run)} targets={','.join(t.name for t in cfg.targets)}")
    r = Runner(cfg, deps, read_log=False)
    for t in cfg.targets:
        u = r.show(t.unit, ["LoadState", "ActiveState"])
        if u is None or u["LoadState"] in ("", "not-found"):
            print(f"unit {t.unit}: ERROR not found")
            errors += 1
        else:
            print(f"unit {t.unit}: {_word(u['LoadState'])}/{_word(u['ActiveState'])}")
        cls, reason = classify(deps.probe_fn, t.host, t.port, t.path, cfg.probe_timeout_s)
        print(f"probe {t.name}: {cls} {reason}")
    for h in cfg.hold_units:
        u = r.show(h, ["LoadState", "ActiveState"])
        print(f"hold {h}: " + ("ERROR systemctl" if u is None else f"{_word(u['LoadState'] or 'none')}/"
                                                                   f"{_word(u['ActiveState'] or 'none')}"))
    try:
        nst = deps.stat(cfg.notify_conf)
    except FileNotFoundError:
        print("notify: disabled")
        return 1 if errors else 0
    except OSError:
        print("notify: ERROR cannot stat notify.conf")
        return 1
    if stat.S_IMODE(nst.st_mode) != 0o600 or (hasattr(os, "geteuid") and nst.st_uid != 0 and nst.st_uid != os.geteuid()):
        print("notify: ERROR notify.conf must be root-owned mode 0600")
        errors += 1
    else:
        print("notify: configured" if load_notify(cfg.notify_conf) else "notify: disabled")
    return 1 if errors else 0


def cmd_status(deps: Deps) -> int:
    try:
        cfg = load_config(deps.paths.conf)
    except Exception:
        cfg = HealConf()
    obj = load_json(cfg.status_path)
    if not obj:
        print("status: none yet")
        return 1
    print(json.dumps(obj, indent=2, sort_keys=True))
    return 0


def main(argv: Optional[List[str]] = None, deps: Optional[Deps] = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel-heal", description="loopback probe / restart timer")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", action="store_true")
    g.add_argument("--alert-unit", metavar="UNIT")
    g.add_argument("--selftest", action="store_true")
    g.add_argument("--status", action="store_true")
    a = ap.parse_args(argv)
    d = deps or Deps()
    if a.run:
        return cmd_run(d)
    if a.alert_unit is not None:
        return cmd_alert_unit(d, a.alert_unit)
    if a.selftest:
        return cmd_selftest(d)
    return cmd_status(d)


if __name__ == "__main__":
    sys.exit(main())
