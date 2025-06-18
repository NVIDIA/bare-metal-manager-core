#!/usr/bin/env bash

DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${DIR}"
mkdir -p /tmp/ipmi_state
exec ipmi_sim -c "${DIR}/lan.conf" -f "${DIR}/cmd.conf" -s /tmp/ipmi_state
