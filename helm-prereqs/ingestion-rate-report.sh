#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# ingestion-rate-report.sh — exact ingestion curves from the DB's own clocks
#
# The Phase 10 CSV (setup-machine-a-tron.sh, #3756) samples counters and so
# measures rates as floors. This report instead reads timestamps the pipeline
# itself recorded, which makes runs exactly comparable for the #3738 knob
# campaign:
#   * machines.created            → machine-creation curve (per-minute + p50/p90 gap)
#   * machine_interfaces.created  → interface registration curve
# Output is plain text; pass --csv for machine-readable per-minute buckets.
#
# Environment:
#   KUBECONFIG, POSTGRES_NS (postgres), NICO_SYSTEM_NS (nico-system)
#   NICO_DB overrides the database selected for the discovered target.
# =============================================================================
set -euo pipefail

POSTGRES_NS="${POSTGRES_NS:-postgres}"
NICO_SYSTEM_NS="${NICO_SYSTEM_NS:-nico-system}"
NICO_DB="${NICO_DB:-}"
CSV=false
[[ "${1:-}" == "--csv" ]] && CSV=true

# A Patroni deployment must have a master. Only use the standalone StatefulSet
# when no Spilo pods exist; this is the database created by DevSpace bootstrap.
SPILO_PODS="$(kubectl get pods -n "$POSTGRES_NS" -l application=spilo \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.spilo-role}{"\n"}{end}' 2>/dev/null \
    || true)"
PG_TARGET="$(awk '$2=="master"{print $1; exit}' <<< "$SPILO_PODS")"
if [[ -n "$SPILO_PODS" ]]; then
    [[ -n "$PG_TARGET" ]] || { echo "ERROR: no Patroni primary in $POSTGRES_NS" >&2; exit 1; }
    NICO_DB="${NICO_DB:-nico_system_nico}"
elif kubectl get statefulset postgres -n "$POSTGRES_NS" >/dev/null 2>&1; then
    PG_TARGET="statefulset/postgres"
    if [[ -z "$NICO_DB" ]]; then
        NICO_DB="$(kubectl get configmap nico-system-nico-database-config -n "$NICO_SYSTEM_NS" \
            -o jsonpath='{.data.DB_NAME}' 2>/dev/null || true)"
        [[ -n "$NICO_DB" ]] || {
            echo "ERROR: database name not found in $NICO_SYSTEM_NS/nico-system-nico-database-config; set NICO_DB" >&2
            exit 1
        }
    fi
else
    echo "ERROR: no PostgreSQL target found in $POSTGRES_NS" >&2
    exit 1
fi
# Surface query failures rather than returning an empty string that later
# parses as a zero row.
q() {
    local out rc=0
    out="$(kubectl exec -n "$POSTGRES_NS" "$PG_TARGET" -- su postgres -c "psql -d $NICO_DB -v ON_ERROR_STOP=1 -tAc \"$1\"" 2>&1)" || rc=$?
    if (( rc != 0 )); then
        echo "ERROR: query failed (rc=$rc): ${out}" >&2
        return "$rc"
    fi
    printf '%s\n' "$out"
}

report_curve() {   # $1 = table  $2 = label
    local tbl="$1" label="$2"
    local stats
    stats="$(q "SELECT count(*) || '|' || min(created) || '|' || max(created) || '|' ||
        round(extract(epoch FROM (max(created) - min(created)))) || '|' ||
        round(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM created)) - extract(epoch FROM min(created))) || '|' ||
        round(percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM created)) - extract(epoch FROM min(created)))
        FROM ${tbl};")"
    [[ -n "$stats" ]] || { echo "${label}: no rows"; return; }
    IFS='|' read -r n first last span p50 p90 <<< "$stats"
    echo "${label}: ${n} rows over ${span}s (first ${first}, last ${last})"
    echo "  p50 at +${p50}s, p90 at +${p90}s, avg $(awk -v n="$n" -v s="$span" 'BEGIN{ if (s>0) printf "%.1f", n*60/s; else printf "n/a" }')/min"
    if $CSV; then
        echo "  per-minute buckets (${label}):"
        q "SELECT date_trunc('minute', created) || ',' || count(*)
           FROM ${tbl}
           GROUP BY date_trunc('minute', created)
           ORDER BY date_trunc('minute', created);" | sed 's/^/    /'
    fi
}

report_curve machines "machines.created"
report_curve machine_interfaces "machine_interfaces.created"

# Terminal-state distribution for context (a knob that destabilizes the
# pipeline shows up as machines wedged mid-state, not just as a slower rate).
echo "state distribution:"
q "SELECT '  ' || coalesce(controller_state->>'state','?') || ': ' || count(*)
   FROM machines
   GROUP BY coalesce(controller_state->>'state','?')
   ORDER BY count(*) DESC;"
