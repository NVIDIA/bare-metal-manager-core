#!/usr/bin/env bash
set -euo pipefail

SITE_FILE=/etc/site-dpu.json

if [[ ! -f "$SITE_FILE" ]]; then
    echo "file not found: $SITE_FILE" >&2
    exit 1
fi

SITE=$(jq -r '.site // empty' "$SITE_FILE")

if [[ -z $SITE ]]; then
    echo "'site' value missing from $SITE_FILE"
    exit 1
fi

DOMAIN=$(jq -r '.domain // empty' "$SITE_FILE")

if [[ -z $DOMAIN ]]; then
    echo "'domain' value missing from $SITE_FILE"
    exit 1
fi

if ! jq -e '
    has("endpoints") and (.endpoints | type == "array")
' $SITE_FILE > /dev/null; then
    echo "'endpoints' is missing from $SITE_FILE or is not an array"
    exit 1
fi

OOB_IP=$(sudo ip -json addr show oob_net0  | jq -r '.[].addr_info[] | select(.family == "inet").local')
EXPECTED_HOSTNAME="$(echo $OOB_IP | tr . -).$SITE.$DOMAIN"
ACTUAL_HOSTNAME=$(hostname)
SCRIPT_DIR=/usr/local/sbin

if [[ "$EXPECTED_HOSTNAME" != "$ACTUAL_HOSTNAME" ]]; then
    hostnamectl set-hostname "$EXPECTED_HOSTNAME"
    "$SCRIPT_DIR"/localhost_alias.sh "$EXPECTED_HOSTNAME"
fi

"$SCRIPT_DIR"/map_endpoints.sh /etc/site-dpu.json
