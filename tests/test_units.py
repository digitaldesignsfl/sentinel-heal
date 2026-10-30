"""Static checks on shipped unit files and install/uninstall scripts (cross-review fixes)."""
from __future__ import annotations

import configparser
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


def _unit(rel: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment]
    cp.read_string(_read(rel))
    return cp


def test_heal_alert_can_write_run_dir() -> None:
    lines = _read("units/heal-alert@.service").splitlines()
    i = lines.index("LogsDirectoryMode=0750")
    assert lines[i + 1] == "ReadWritePaths=-/run/sentinel-heal"


def test_main_unit_preserves_run_dir() -> None:
    svc = _unit("units/sentinel-heal.service")["Service"]
    assert svc["RuntimeDirectory"] == "sentinel-heal"
    assert svc["RuntimeDirectoryPreserve"] == "yes"


def test_backstop_agent_burst_20_otherwise_same() -> None:
    a, b = _unit("units/backstop-agent.conf")["Unit"], _unit("units/backstop.conf")["Unit"]
    assert a["StartLimitBurst"] == "20" and b["StartLimitBurst"] == "5"
    assert {k: v for k, v in a.items() if k != "StartLimitBurst"} == \
           {k: v for k, v in b.items() if k != "StartLimitBurst"}


def test_install_maps_dropins_per_target() -> None:
    s = _read("install.sh")
    pairs = re.findall(r'"\$SRC/units/([\w.-]+\.conf)" "\$SD/([\w-]+)\.service\.d/50-sentinel-heal\.conf"', s)
    assert sorted(pairs) == sorted([("onfailure.conf", "nginx"), ("backstop.conf", "ollama"),
                                    ("backstop-agent.conf", "sentinel-agent")])
    assert "units/backstop-agent.conf" in s.split("# 2. program")[0]   # precondition list


def test_uninstall_removes_agent_dropin() -> None:
    s = _read("uninstall.sh")
    assert "for t in nginx ollama sentinel-agent" in s
    assert 'rm -f "$SD/$t.service.d/50-sentinel-heal.conf"' in s


def test_install_verify_targets_rc_only() -> None:
    s = _read("install.sh")
    assert '|| die "systemd-analyze verify failed (targets)' in s
    assert '[[ -z "$verify_out" ]] || die "systemd-analyze verify output (targets)' not in s
    assert '|| die "systemd-analyze verify failed (heal units)' in s
    assert '[[ -z "$verify_out" ]] || die "systemd-analyze verify output (heal units)' in s


def test_staging_path_not_under_opt() -> None:
    for rel in ("README.md", "install.sh", "units/sentinel-heal.service"):
        s = _read(rel)
        assert "/opt/hive_vps/sentinel-heal" not in s, rel
    assert "/usr/local/src/sentinel-heal" in _read("README.md")
