#!/usr/bin/env bash
# sentinel-heal install (design §10). Idempotent. Run as root from the staged copy (root:root):
#   cd /usr/local/src/sentinel-heal && sudo DRY_RUN=1 bash install.sh
# Never overwrites /etc/sentinel-heal/heal.conf, never creates notify.conf, never touches
# nginx.service.d/restart.conf or ollama.service.d/cpu-limit.conf.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETC=/etc/sentinel-heal
SD=/etc/systemd/system
BIN=/usr/local/sbin/sentinel-heal
TARGETS=(nginx ollama sentinel-agent)

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

# 1. preconditions
[[ "$(id -u)" -eq 0 ]] || die "must run as root"
python3 -c 'import sys; sys.exit(sys.version_info < (3,10))' || die "python3 >= 3.10 required"
for f in sentinel_heal.py heal.conf units/sentinel-heal.service units/sentinel-heal.timer \
         "units/heal-alert@.service" units/backstop.conf units/backstop-agent.conf units/onfailure.conf logrotate/sentinel-heal; do
    [[ -f "$SRC/$f" ]] || die "missing $SRC/$f"
done
python3 -m py_compile "$SRC/sentinel_heal.py" || die "sentinel_heal.py does not compile"
case "${DRY_RUN:-}" in ""|0|1) ;; *) die "DRY_RUN must be 0 or 1" ;; esac

# 2. program
install -o root -g root -m 0755 "$SRC/sentinel_heal.py" "$BIN"

# 3. config: only if absent
install -d -o root -g root -m 0755 "$ETC"
if [[ ! -e "$ETC/heal.conf" ]]; then
    install -o root -g root -m 0644 "$SRC/heal.conf" "$ETC/heal.conf"
    say "installed $ETC/heal.conf (dry_run = 1)"
else
    say "$ETC/heal.conf exists; not overwritten"
    if ! cmp -s "$SRC/heal.conf" "$ETC/heal.conf"; then
        say "live heal.conf differs from repo copy:"
        diff -u "$ETC/heal.conf" "$SRC/heal.conf" || true
    fi
fi
if [[ "${DRY_RUN:-}" == "0" ]]; then
    sed -i -E 's/^dry_run[[:space:]]*=[[:space:]]*1([[:space:]]|$)/dry_run = 0\1/' "$ETC/heal.conf"
    say "DRY_RUN=0 passed: dry_run set to 0 in $ETC/heal.conf"
fi
grep -E '^dry_run' "$ETC/heal.conf" || true

# 4. notify.conf: never created here
if [[ ! -e "$ETC/notify.conf" ]]; then
    say "notify.conf missing — create root 0600 by hand; notify disabled until then"
fi

# 5. units and drop-ins (only 50-sentinel-heal.conf is ever written)
install -o root -g root -m 0644 "$SRC/units/sentinel-heal.service" "$SD/sentinel-heal.service"
install -o root -g root -m 0644 "$SRC/units/sentinel-heal.timer" "$SD/sentinel-heal.timer"
install -o root -g root -m 0644 "$SRC/units/heal-alert@.service" "$SD/heal-alert@.service"
for t in "${TARGETS[@]}"; do
    install -d -o root -g root -m 0755 "$SD/$t.service.d"
done
install -o root -g root -m 0644 "$SRC/units/onfailure.conf" "$SD/nginx.service.d/50-sentinel-heal.conf"
install -o root -g root -m 0644 "$SRC/units/backstop.conf" "$SD/ollama.service.d/50-sentinel-heal.conf"
# sentinel-agent gets Burst=20 (backstop-agent.conf): broker-driven restarts must not trip the limit; ollama keeps Burst=5
install -o root -g root -m 0644 "$SRC/units/backstop-agent.conf" "$SD/sentinel-agent.service.d/50-sentinel-heal.conf"
if [[ ! -e "$SD/nginx.service.d/restart.conf" ]]; then
    say "WARNING: $SD/nginx.service.d/restart.conf absent: nginx has no Restart=; its OnFailure hook fires on the first crash"
fi

# 6. logrotate
install -o root -g root -m 0644 "$SRC/logrotate/sentinel-heal" /etc/logrotate.d/sentinel-heal

# 7. reload + verify (heal units: abort on any output; targets: abort on rc only)
systemctl daemon-reload
verify_out="$(systemd-analyze verify "$SD/sentinel-heal.service" "$SD/sentinel-heal.timer" "$SD/heal-alert@.service" 2>&1)" \
    || die "systemd-analyze verify failed (heal units): $verify_out"
[[ -z "$verify_out" ]] || die "systemd-analyze verify output (heal units): $verify_out"
# PLAN_GAP (§10 step 7): the design verifies /etc/systemd/system/<t>.service, but nginx (and
# possibly ollama) ship their unit under /lib/systemd/system. Implemented as: verify the unit's
# FragmentPath as systemd resolves it (drop-ins are loaded with it).
target_files=()
for t in "${TARGETS[@]}"; do
    frag="$(systemctl show -p FragmentPath --value "$t.service")"
    [[ -n "$frag" && -f "$frag" ]] || die "cannot resolve unit file for $t.service"
    target_files+=("$frag")
done
# target units are not ours: vendor units commonly emit harmless warnings, so rc only; print output
verify_out="$(systemd-analyze verify "${target_files[@]}" 2>&1)" \
    || die "systemd-analyze verify failed (targets): $verify_out"
[[ -z "$verify_out" ]] || say "systemd-analyze verify output (targets, rc 0, not fatal): $verify_out"

# 8. self-test, then one real run under the real sandbox
"$BIN" --selftest || die "selftest failed"
systemctl start sentinel-heal.service || die "first sentinel-heal.service run failed (see journalctl -u sentinel-heal)"
tail -n 3 /var/log/sentinel-heal/heal.jsonl 2>/dev/null || say "no heal.jsonl rows yet (all OK is silent)"

# 9. enable timer
systemctl enable --now sentinel-heal.timer
systemctl list-timers sentinel-heal.timer --no-pager

# 10. targets are not restarted here
say "done. nginx/ollama/sentinel-agent were NOT restarted; drop-ins apply via daemon-reload"
systemctl show -p Restart,OnFailure nginx.service ollama.service sentinel-agent.service || true
