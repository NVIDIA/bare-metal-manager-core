# NVSWITCH telemetry GB200 source matrix

Generated from `.omx/artifacts/nvswitch_rows.csv` for rows where `Device (CompClass)` is NVSWITCH and one of the GB200 columns is `Yes`:

- `Applicable for GB200 NVL HMC`
- `Applicable for GB200 NVL BMC`
- `Applicable for GB200 NVL NvswitchTray`

CSV matrix: `docs/architecture/health/nvswitch_telemetry_gb200_matrix.csv`

## Counts

- Total GB200-applicable NVSWITCH rows: 193

### Implementation status

- already-covered-regression-required: 5
- blocker-source-resolution: 2
- gap-needs-implementation: 183
- partial-needs-implementation: 3

### Current coverage

- catalog_no_source_gap: 2
- covered_host_gnmi: 4
- covered_host_nmxt: 1
- gap: 183
- partial_host: 3

### Primary source

- BLOCKER source resolution: 2
- NMX-T: 57
- NVOS CLI: 36
- NVOS gNMI: 97
- Redfish Fabric/Switch/Port: 1

## Execution rules

- Every row must keep `primary_source`, `fallback_source`, `source_precedence`, and `duplicate_alias_policy` populated before implementation is marked complete.
- Default duplicate policy is one canonical series per catalog row; source-qualified duplicates require source-path proof and consumer-safety rationale.
- Rows marked `blocker-source-resolution` are not deferred; they require immediate source-resolution or escalation.
- Live GB200 validation happens after the branch is built, tested, linted, pushed, and reviewed.
