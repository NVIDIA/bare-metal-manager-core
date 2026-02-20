#!/usr/bin/env bash
set -euo pipefail

#
# Parses a json file containing an array of `fqdn -> ip-addr` mappings at the
# given dot-delimited json key (such as "a.b.c") and adds them to /etc/hosts if
# they don't already exist. The mappings in the specified array are assumed to
# be in this form:
#
#   {
#      "fqdn": "some.fqdn",
#      "ip": "10.0.0.1"
#   },
#

JSON_FILE="$1"
JSON_KEY="${2:-endpoints}"
HOSTS_FILE="/etc/hosts"
NEWLINE_ADDED=false

if [[ ! -f "$JSON_FILE" ]]; then
    echo "file not found: $JSON_FILE" >&2
    exit 1
fi

if ! jq -e --arg key "$JSON_KEY" 'has($key)' "$JSON_FILE" > /dev/null; then
    echo "'$JSON_KEY' not found in $JSON_FILE" >&2
    exit 1
fi

jq -r --arg key "$JSON_KEY" '
    .[$key][] | "\(.ip) \(.fqdn)"
' "$JSON_FILE" | while read -r ip fqdn; do
    # Trim whitespace
    fqdn=$(echo "$fqdn" | xargs)
    ip=$(echo "$ip" | xargs)

    [[ -z "$fqdn" ]] && continue
    [[ -z "$ip" ]] && continue

    # Check if fqdn already present in /etc/hosts
    if ! grep -qE "[[:space:]]$fqdn(\$|[[:space:]])" "$HOSTS_FILE"; then
        echo "Adding $ip $fqdn to $HOSTS_FILE"
        if [[ $NEWLINE_ADDED == "false" ]]; then
            echo >> $HOSTS_FILE
            NEWLINE_ADDED=true
        fi
        printf "%s %s\n" "$ip" "$fqdn" >> "$HOSTS_FILE"
    else
        echo "Entry for $fqdn already exists in $HOSTS_FILE"
    fi
done
