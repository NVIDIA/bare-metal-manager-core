#!/usr/bin/env bash
set -euo pipefail

HOSTS_FILE="/etc/hosts"
HOSTNAME="$1"

if [[ -z "${HOSTNAME}" ]]; then
    echo "Usage: $0 <hostname>" >&2
    exit 1
fi

PATTERN='^127\.0\.0\.1[[:space:]]+localhost\.localdomain[[:space:]]+localhost'
PATTERN+='(\s|$).*'"${HOSTNAME}"'\b'

# If the hostname is already present on the 127.0.0.1 localhost line, nothing to do
if grep -qE "$PATTERN" "$HOSTS_FILE"; then
    echo "$HOSTNAME is already aliased to 127.0.0.1, nothing to do."
    exit 0
fi

# Otherwise, append it to that line
tmp="$(mktemp)"
awk -v h="$HOSTNAME" '
    $1 == "127.0.0.1" && $2 == "localhost.localdomain" && $3 == "localhost" {
        # append hostname once
        print $0, h
        next
    }
    { print }
' "$HOSTS_FILE" > "$tmp"

cp "$tmp" "$HOSTS_FILE"
rm -f "$tmp"
