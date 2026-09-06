#!/usr/bin/env bash
# Last-line acceptance checks on generated artifacts.
#
# These duplicate checks the Python gates already perform. That redundancy is
# deliberate: they are written in a different language, against the published
# bytes rather than in-memory objects, so a bug in the generator cannot silently
# disable both. Any hit here means the build must not be published.
#
#     scripts/acceptance-checks.sh dist

set -euo pipefail

DIST="${1:-dist}"
STATUS=0
SECTION_STATUS=0

# STATUS counts failures rather than latching a flag, so section_end can tell
# whether *this* section failed even after an earlier one already did.
fail() {
    printf 'FAIL  %s\n' "$1" >&2
    STATUS=$((STATUS + 1))
}

# A section reports "ok" only if nothing failed inside it, so a green line can
# never sit next to a red one for the same check.
section_start() {
    SECTION_STATUS="$STATUS"
}

section_end() {
    if [ "$STATUS" -eq "$SECTION_STATUS" ]; then
        printf 'ok    %s\n' "$1"
    fi
}

for name in cn-ipv4.txt cn-domains.txt cn-direct.txt checksums.txt metadata.json; do
    if [ ! -f "$DIST/$name" ]; then
        fail "$name is missing"
    fi
done
[ "$STATUS" -eq 0 ] || exit 1

# --- no default or otherwise catastrophic route ------------------------------
section_start
for cidr in 0.0.0.0/0 0.0.0.0/1 128.0.0.0/1 0.0.0.0/2 0.0.0.0/8 10.0.0.0/8 \
            127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 \
            224.0.0.0/4 240.0.0.0/4; do
    if grep -Fxq "$cidr" "$DIST/cn-ipv4.txt" || grep -Fxq "$cidr" "$DIST/cn-direct.txt"; then
        fail "dangerous network present: $cidr"
    fi
done
section_end "no dangerous IPv4 networks"

# --- no never-direct domain, and no rule that would encompass one -------------
# A generated "com" line would match google.com just as surely as an explicit
# google.com line would, so every parent suffix is checked too.
section_start
while IFS= read -r raw; do
    domain="${raw%%#*}"
    domain="$(printf '%s' "$domain" | tr -d '[:space:]')"
    [ -n "$domain" ] || continue

    candidate="$domain"
    while [ -n "$candidate" ]; do
        if grep -Fxq "$candidate" "$DIST/cn-domains.txt"; then
            fail "never-direct domain '$domain' is matched by generated rule '$candidate'"
        fi
        case "$candidate" in
            *.*) candidate="${candidate#*.}" ;;
            *) candidate="" ;;
        esac
    done
done < config/never-direct-domains.txt
section_end "no never-direct domain leaked"

# --- byte-level shape --------------------------------------------------------
section_start
for name in cn-ipv4.txt cn-domains.txt cn-direct.txt checksums.txt; do
    file="$DIST/$name"
    if [ -s "$file" ] && [ "$(tail -c 1 "$file" | wc -l)" -eq 0 ]; then
        fail "$name has no final newline"
    fi
    if LC_ALL=C grep -q $'\r' "$file"; then
        fail "$name contains CR characters"
    fi
    if [ "$(head -c 3 "$file" | od -An -tx1 | tr -d ' \n')" = "efbbbf" ]; then
        fail "$name starts with a UTF-8 BOM"
    fi
    if LC_ALL=C grep -q '^[[:space:]]*$' "$file"; then
        fail "$name contains a blank line"
    fi
done
section_end "artifacts are LF, BOM-free and end with a newline"

# --- checksums actually match ------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    section_start
    (cd "$DIST" && sha256sum -c checksums.txt >/dev/null 2>&1) \
        || fail "checksums.txt does not verify"
    section_end "checksums verify"
fi

# --- combined file is exactly the union of its parts -------------------------
section_start
if ! diff -q <(cat "$DIST/cn-domains.txt" "$DIST/cn-ipv4.txt") "$DIST/cn-direct.txt" >/dev/null; then
    fail "cn-direct.txt is not cn-domains.txt followed by cn-ipv4.txt"
fi
section_end "cn-direct.txt matches its components"

if [ "$STATUS" -ne 0 ]; then
    printf '\n%s check(s) failed.\n' "$STATUS" >&2
    printf '\nSECURITY GATE FAILED\n\nPublication blocked. The previous release remains active.\n' >&2
    exit 1
fi
exit 0
