#!/usr/bin/env bash
# sentinel-heal uninstall (design §10). Idempotent. Usage: sudo bash uninstall.sh [--purge]
# Never touches nginx.service.d/restart.conf or ollama.service.d/cpu-limit.conf.
# notify.conf is always left for the operator, even with --purge.
set -euo pipefail

ETC=/etc/sentinel-heal
SD=/etc/systemd/system
PURGE=0

die() { echo "uninstall.sh: $*" >&2; exit 1; }
say() { echo "uninstall.sh: $*"; }

case "${1:-}" in
    "") ;;
    --purge) PURGE=1 ;;
    *) die "usage: uninstall.sh [--purge]" ;;
esac
[[ "$(id -u)" -eq 0 ]] || die "must run as root"

systemctl disable --now sentinel-heal.timer 2>/dev/null || true
systemctl stop sentinel-heal.service 2>/dev/null || true

rm -f "$SD/sentinel-heal.service" "$SD/sentinel-heal.timer" "$SD/heal-alert@.service"
for t in nginx ollama sentinel-agent; do
    # 50-sentinel-heal.conf is onfailure.conf (nginx), backstop.conf (ollama) or
    # backstop-agent.conf (sentinel-agent) under one name
    rm -f "$SD/$t.service.d/50-sentinel-heal.conf"
    # remove the drop-in dir only if heal left it empty (restart.conf / cpu-limit.conf keep it)
    rmdir "$SD/$t.service.d" 2>/dev/null || true
done
systemctl daemon-reload
systemctl reset-failed sentinel-heal.service 2>/dev/null || true

rm -f /usr/local/sbin/sentinel-heal /etc/logrotate.d/sentinel-heal

if [[ "$PURGE" -eq 1 ]]; then
    rm -rf /var/log/sentinel-heal /var/lib/sentinel-heal /run/sentinel-heal
    if [[ -d "$ETC" ]]; then
        find "$ETC" -mindepth 1 -maxdepth 1 ! -name notify.conf -exec rm -rf -- {} +
        rmdir "$ETC" 2>/dev/null || say "kept $ETC/notify.conf for the operator"
    fi
    say "purged config, logs and state (notify.conf, if any, kept)"
else
    say "kept $ETC/, /var/log/sentinel-heal/, /var/lib/sentinel-heal/ (use --purge to remove)"
fi
say "done; nginx.service.d/restart.conf and ollama.service.d/cpu-limit.conf untouched"
