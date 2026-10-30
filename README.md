# sentinel-heal

A lightweight, robust, probe-timer self-healing watchdog for systemd services with integrated [ntfy](https://ntfy.sh) alerting and zero external runtime dependencies (pure Python 3.10+ standard library).

---

## Origin

`sentinel-heal` was originally built as the resilience watchdog for a multi-node autonomous homelab infrastructure stack (**Sovereign Hive**). It is extracted here as a clean, standalone, open-source utility for system administrators, DevOps engineers, and homelab operators who need deterministic service recovery beyond basic systemd `Restart=always`.

---

## Overview: Why sentinel-heal?

Systemd's native `Restart=always` only reacts when a process **dies or crashes** (SIGSEGV, abnormal exit). It cannot detect:
- Processes that are **alive in kernel tables but completely hung / deadlock** (e.g. frozen event loops, stuck database connection pools, thread starvation).
- HTTP listeners returning persistent `5xx` errors while remaining active.
- Flapping services that restart repeatedly without operator notification.

`sentinel-heal` runs on a recurring systemd timer (default: every 60s), probing loopback endpoints (`http://127.0.0.1:<port>/path`). When a target service fails probes consecutively across multiple cycles (**strikes**), `sentinel-heal` initiates a managed restart, verifies health recovery, enforces hourly and daily rate limits (**restart caps**), and dispatches notifications via ntfy.

---

## Key Features

- **Strike Discipline:** Avoids transient blips by requiring configurable consecutive failed probes (default: 2 strikes) before initiating a restart.
- **Dry-Run Soak Mode:** Ships by default with `dry_run = 1`. In dry-run mode, all probes, strike logic, audit logs, and status updates run identically to production, but restart commands are withheld.
- **Fail-Safe Live Gate:** Live restarts (`dry_run = 0`) are hard-blocked unless a valid, operator-configured notification channel (`notify.conf`) exists. If notification is absent, heal automatically falls back to safe dry-run mode.
- **Restart Caps:** Hard limits on restart frequency (e.g. max 3 restarts per unit per rolling hour, max 6 per day) to prevent destructive restart storms when a service is permanently broken.
- **Skip Rules & Safety Interlocks:**
  - **Hold Units:** Skips targets when maintenance or backup units are active/activating.
  - **Boot Grace:** Skips probes during system boot (`min_uptime_s`).
  - **Recently Started:** Enforces cooldown grace periods (`min_active_s`) after service activation.
  - **Interface Check:** Optional requirement that an interface (e.g. `tailscale0`) has an IP before attempting restart.
  - **Busy Marker:** Respects long-running background tasks via file markers (e.g. `/run/myapp/busy`).
- **External Restart Detection:** Tracks PID and InvocationID changes from external actions (`systemctl restart`), logging `EXTERNAL_RESTART` and resetting strikes.
- **Audit Trails:** Append-only structured JSONL logging (`heal.jsonl`) + atomic state projection (`status.json`).
- **Operational Controls:** Instant runtime pause (`touch /run/sentinel-heal/pause`) or permanent killswitch (`touch /etc/sentinel-heal/KILL`).

---

## Deployment & Installation

### Requirements
- Linux with systemd
- Python 3.10 or higher (uses stdlib only; zero pip dependencies)

### Quick Install

```bash
git clone https://github.com/digitaldesignsfl/sentinel-heal.git
cd sentinel-heal

# Install in dry-run mode (recommended for initial soak)
sudo DRY_RUN=1 bash install.sh
```

The installer:
1. Installs the executable to `/usr/local/sbin/sentinel-heal`.
2. Creates `/etc/sentinel-heal/heal.conf` (if not already present).
3. Installs `sentinel-heal.service`, `sentinel-heal.timer`, and `heal-alert@.service` in `/etc/systemd/system/`.
4. Installs systemd drop-ins for watched services (OnFailure alert hooks and restart backstops).
5. Installs logrotate rules in `/etc/logrotate.d/sentinel-heal`.
6. Reloads systemd and enables `sentinel-heal.timer`.

---

## Configuration

Configuration is located at `/etc/sentinel-heal/heal.conf` (mode `0644 root:root`):

```ini
[heal]
dry_run = 1                 ; 1 = log DRY_RUN rows, never restart. Set 0 for active healing.
interval_s = 60             ; Informational cadence spacing.
strikes = 2                 ; Consecutive DOWN probes required before triggering a restart.
probe_timeout_s = 5         ; Connect and read timeout per probe.
min_active_s = 180          ; Grace period: skip target if started < 180s ago.
min_uptime_s = 300          ; Skip all checks if system booted < 300s ago.
busy_max_age_s = 1800       ; Marker files older than this are treated as stale.
hold_units =                ; Space-separated units that pause healing while active.
cap_hour = 3                ; Maximum restart attempts per rolling hour.
cap_day = 6                 ; Maximum restart attempts per rolling 24 hours.
poll_s = 2                  ; Interval between restart job status checks.
restart_timeout_grace_s = 10 ; Extra margin added to systemd TimeoutStopSec.
log_path = /var/log/sentinel-heal/heal.jsonl
status_path = /var/lib/sentinel-heal/status.json
run_dir = /run/sentinel-heal
notify_conf = /etc/sentinel-heal/notify.conf
notify_repeat_s = 3600      ; Rate limit duplicate notifications for the same event.

[target:api]
unit = api.service
probe = http://127.0.0.1:8080/health
post_restart_wait_s = 15,30 ; Health check polling delays after restart.

[target:nginx]
unit = nginx.service
probe = http://127.0.0.1:80/
post_restart_wait_s = 15
```

### Notification Configuration

Create `/etc/sentinel-heal/notify.conf` with restricted permissions (`chmod 0600 root:root`):

```ini
NTFY_URL=https://ntfy.sh/your-secret-alert-topic
NTFY_TOKEN=  # Optional: Bearer token for protected ntfy topics
```

---

## Operations Cheat Sheet

| Task | Command | Effect |
|---|---|---|
| **View live status** | `sentinel-heal --status` | Outputs formatted summary from `status.json` |
| **Inspect raw logs** | `tail -f /var/log/sentinel-heal/heal.jsonl` | Streams JSON-lines audit trail |
| **Run immediate probe** | `sudo systemctl start sentinel-heal.service` | Triggers a probe cycle immediately |
| **Pause temporarily** | `sudo touch /run/sentinel-heal/pause` | Pauses probes; automatically clears on reboot |
| **Pause permanently** | `sudo touch /etc/sentinel-heal/pause` | Pauses probes; persists across reboots |
| **Emergency killswitch**| `sudo touch /etc/sentinel-heal/KILL` | Systemd ExecCondition aborts all runs immediately |
| **Resume operations** | `sudo rm -f /run/sentinel-heal/pause /etc/sentinel-heal/pause /etc/sentinel-heal/KILL` | Resumes normal timer execution |

---

## Uninstall

```bash
# Keep configuration and audit logs:
sudo bash uninstall.sh

# Complete purge (removes logs, state, and units):
sudo bash uninstall.sh --purge
```

---

## Testing

Run unit tests locally (no root or network required):

```bash
pip install pytest
pytest tests -q
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
