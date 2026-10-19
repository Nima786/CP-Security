#!/bin/sh
# CP-Security installer. Run it as root on the CyberPanel server:
#
#     curl -fsSL https://github.com/Nima786/CP-Security/releases/latest/download/install.sh | sh
#
# or, from a copy of this repository:   sh install.sh
#
# It installs a numbered release, never "whatever is on the main branch", and checks the download against
# the release's published fingerprint. To install one particular version:
#
#     curl -fsSL https://github.com/Nima786/CP-Security/releases/download/v0.2.0/install.sh | sh
#
# It asks a few questions (sub-domain, port, username, password) and then does everything.
# Nothing is changed before you have answered the last question and confirmed.
set -eu

REPO="Nima786/CP-Security"
# The published copy of this script has the real version number here (the release workflow fills it in).
VERSION="@@VERSION@@"

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

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else die "sha256sum is needed to check the download."; fi
}

# --- the files: from this folder if we are in a copy of the repository, else a numbered release ----
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$HERE" ] && [ -d "$HERE/cpsec" ] && [ -f "$HERE/VERSION" ]; then
    SRC="$HERE"
else
    command -v curl >/dev/null 2>&1 || die "curl is needed to download CP-Security."
    command -v tar >/dev/null 2>&1 || die "tar is needed to unpack CP-Security."
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    WANT="$VERSION"
    if [ "$WANT" = "@@""VERSION@@" ]; then
        # this copy of the script is not tied to a version: use the newest release
        WANT="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" |
                sed -n 's#.*/releases/tag/v\{0,1\}\([0-9][0-9A-Za-z.+-]*\)$#\1#p')"
        [ -n "$WANT" ] || die "no release of CP-Security was found at github.com/$REPO/releases."
    fi
    BASE="https://github.com/$REPO/releases/download/v$WANT"
    FILE="cp-security-$WANT.tar.gz"
    say "Downloading CP-Security $WANT ..."
    curl -fsSL "$BASE/$FILE" -o "$TMP/$FILE" || die "the download failed. Check that this server can reach github.com."
    curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "the checksum list for version $WANT could not be downloaded."
    EXPECTED="$(grep "  $FILE\$" "$TMP/SHA256SUMS" | cut -d' ' -f1 | head -n 1)"
    [ -n "$EXPECTED" ] || die "version $WANT has no published checksum, so it was not installed."
    [ "$(sha256_of "$TMP/$FILE")" = "$EXPECTED" ] || die "the download does not match its published checksum, so it was not installed."
    say "Download checked against the published fingerprint."
    tar -xzf "$TMP/$FILE" -C "$TMP"
    SRC="$TMP/cp-security-$WANT"
    [ -d "$SRC/cpsec" ] && [ -f "$SRC/VERSION" ] || die "the download did not contain CP-Security."
fi

# --- questions need a keyboard, even when this script was piped in from curl ------------------
cd "$SRC"
if [ ! -t 0 ] && (: </dev/tty) 2>/dev/null; then
    exec "$PY" -m cpsec install "$@" </dev/tty
fi
exec "$PY" -m cpsec install "$@"
