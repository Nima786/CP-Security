#!/bin/sh
# Takes CP-Security away again. Run as root:   sh uninstall.sh   (add --purge to delete the settings too)
# It asks before removing anything, and asks separately about the protections and the admin lock.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Problem: please run this as root." >&2; exit 1; }
[ -d /opt/cp-security/cpsec ] || { echo "CP-Security does not seem to be installed here (no /opt/cp-security)." >&2; exit 1; }
cd /opt/cp-security
PY="$(command -v python3.13 || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)"
if [ ! -t 0 ] && (: </dev/tty) 2>/dev/null; then
    exec "$PY" -m cpsec uninstall "$@" </dev/tty
fi
exec "$PY" -m cpsec uninstall "$@"
