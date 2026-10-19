#!/bin/sh
# CP-Security installer. Run it as root on the CyberPanel server:
#
#     curl -fsSL https://raw.githubusercontent.com/Nima786/CP-Security/main/install.sh | sh
#
# or, from a copy of this repository:   sh install.sh
#
# To install one fixed version instead of the newest:   CPSEC_REF=v0.2.0 sh install.sh
# It asks a few questions (sub-domain, port, username, password) and then does everything.
# Nothing is changed before you have answered the last question and confirmed.
set -eu

REPO="Nima786/CP-Security"
REF="${CPSEC_REF:-main}"

say() { printf '%s\n' "$*"; }
die() { printf 'Problem: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run this as root (log in as root, or put sudo in front)."
[ "$(uname -s)" = "Linux" ] || die "CP-Security runs on Linux servers only."

# --- a Python that is new enough (3.10 or newer) ---------------------------------------------
find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

PY="$(find_python || true)"
if [ -z "$PY" ]; then
    if command -v dnf >/dev/null 2>&1; then
        say "Python 3.10 or newer is needed. Installing python3.11 with dnf ..."
        dnf install -y python3.11 >/dev/null || die "could not install python3.11."
        PY="$(find_python || true)"
    fi
fi
[ -n "$PY" ] || die "Python 3.10 or newer is needed (Ubuntu 22.04 and newer, AlmaLinux 9 with python3.11)."

# --- the files: from this folder if we are in a copy of the repository, else download them ----
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -d "$HERE/cpsec" ] && [ -f "$HERE/VERSION" ]; then
    SRC="$HERE"
else
    command -v curl >/dev/null 2>&1 || die "curl is needed to download CP-Security."
    command -v tar >/dev/null 2>&1 || die "tar is needed to unpack CP-Security."
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    say "Downloading CP-Security ($REF) from github.com/$REPO ..."
    curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" -o "$TMP/cps.tar.gz" ||
        die "the download failed. Check that this server can reach github.com."
    tar -xzf "$TMP/cps.tar.gz" -C "$TMP"
    SRC="$(find "$TMP" -maxdepth 2 -type f -name VERSION -exec dirname {} \; | head -n 1)"
    [ -n "$SRC" ] && [ -d "$SRC/cpsec" ] || die "the download did not contain CP-Security."
fi

# --- questions need a keyboard, even when this script was piped in from curl ------------------
cd "$SRC"
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec "$PY" -m cpsec install "$@" </dev/tty
fi
exec "$PY" -m cpsec install "$@"
