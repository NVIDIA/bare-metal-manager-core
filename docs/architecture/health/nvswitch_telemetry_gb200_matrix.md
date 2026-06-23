# NVSWITCH telemetry GB200 source matrix

Generated from Stage 0 live-probe results (`nvswitch-stage0-live-coverage-20260620.md`) via
`catalog-coverage-final.csv`. Supersedes the pre-live-validation matrix generated from the raw
catalog extraction.

CSV matrix: `docs/architecture/health/nvswitch_telemetry_gb200_matrix.csv`

Columns: `catalog_row`, `metric_param_name`, `corrected_primary_source`, `final_status`,
`disposition`, `match_detail`.

## Counts

- Total GB200-applicable NVSWITCH rows: 193

### Disposition (post-live-probe)

| Disposition    | Count | Meaning                                                               |
|----------------|-------|-----------------------------------------------------------------------|
| implemented    | 149   | PRESENT/RESOLVED-LIVE allowlist hit, or IMPLEMENTED (MAX-SPEED via NVUE REST) |
| blocker        | 44    | ABSENT-BLOCKER (leaf not live), BLOCKER-THRESHOLD (config-only), or BLOCKER-STRING (string-valued) |

### final_status breakdown

| final_status      | Count |
|-------------------|-------|
| PRESENT           | 132   |
| RESOLVED-LIVE     | 16    |
| IMPLEMENTED       | 1     |
| ABSENT-BLOCKER    | 17    |
| BLOCKER-THRESHOLD | 21    |
| BLOCKER-STRING    | 6     |

## Blocker escalations

See `nvswitch_telemetry_gb200_live_validation.md` section "Blocker escalations (Stage 0)" for the
full annotated list of 44 rows, grouped by root cause, with resolution path and re-probe
conditions.

## Notes on implemented rows

- **PRESENT** rows have an explicit gNMI or NMX-T allowlist mapping confirmed live by the Stage 0
  probe. No further work required before merge.
- **RESOLVED-LIVE** rows have no direct catalog-listed source but a live token match was found in
  gNMI or NMX-T output. Match tokens are recorded in `match_detail`. These are accepted as
  covered; if live validation on a production rig disputes a mapping, re-escalate immediately.
- **IMPLEMENTED — MAX-SPEED (row 894):** sourced from NVUE REST `/nvue_v1/platform/environment/fan`
  `.max-speed` (not Redfish — confirmed live). The 4 `/platform-general` memory/disk rows
  (`886/887/888/889`) are PRESENT via the new gNMI `platform-general` subscribe path.

## Notes on blocker rows

No row is marked "deferred." Every blocker has an explicit escalation disposition:

- **BLOCKER-THRESHOLD (21 rows):** The catalog entry represents a threshold/limit/alarm-state
  value, not a streamed telemetry counter. These are configuration parameters unavailable as live
  gNMI leaves. Source owner must confirm whether a future gNMI path or Redfish sensor threshold
  can expose them; until confirmed they cannot be implemented without a new data source.
- **BLOCKER-STRING (6 rows):** string-valued catalog rows with no numeric encoding — `CONTACT`,
  `LOCATION`, `NODE-DESCRIPTION` (platform), `ASIC-NAME`, `PHY-MANAGER-STATE`, `VL-CAPABILITIES`.
  Present live but cannot be emitted as numeric metrics; need a string/label export path (tracked
  as #11), or enum-coding for the FSM-style ones. Not silently dropped — escalated.
- **ABSENT-BLOCKER — cable/transceiver alarm leaves (9 rows: 981-986, 2293, 2296-2299):** gNMI
  leaves exist in the schema but returned no data on the test rig. Likely empty due to an uncabled
  switch. Re-probe on a cabled switch before treating as a permanent blocker.
- **ABSENT-BLOCKER — TIME-SINCE-LASTS-CLEAR (row 909):** gNMI leaf
  `/interfaces/interface/phy-diag/state/time-since-last-clear-min` not live. Escalate to NVOS
  gNMI owner for NVOS version confirmation.
- **ABSENT-BLOCKER — PLR-CODES-LOSS (row 931):** NMX-T field `HiRetransmissionRate` not live.
  Escalate to NMX-T owner.
- **ABSENT-BLOCKER — NMX-T RDMA queue counters (rows 1706-1708):** RQ-NUM-WRFE, RQ-NUM-LLE,
  SQ-NUM-WRFE — NMX-T fields `rq_num_wrfe`, `rq_num_lle`, `sq_num_wrfe` not live. Escalate to
  NMX-T/RDMA owner.
- **ABSENT-BLOCKER — OS-KERNEL (row 765):** CLI-only, no gNMI or NMX-T token match. Requires a
  new CLI collector or NVOS gNMI exposure; escalate to NVOS owner.
