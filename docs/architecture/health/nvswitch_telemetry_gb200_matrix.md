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
| implemented    | 177   | PRESENT allowlist hit, IMPLEMENTED (NVUE REST / info / enum-coded / discovered live source), or covered by an existing label |
| blocker        | 16    | ABSENT-BLOCKER — leaf/family not live on this platform |

### final_status breakdown

| final_status      | Count |
|-------------------|-------|
| PRESENT           | 136   |
| IMPLEMENTED       | 41    |
| ABSENT-BLOCKER    | 16    |

## Blocker escalations

See `nvswitch_telemetry_gb200_live_validation.md` section "Blocker escalations (Stage 0)" for the
full annotated list of 16 rows, grouped by root cause, with resolution path and re-probe
conditions.

## Notes on implemented rows

- **PRESENT** rows have an explicit gNMI or NMX-T allowlist mapping confirmed live by the Stage 0
  probe. No further work required before merge.
- **IMPLEMENTED via discovered live sources (5 rows)** — these had no direct catalog-listed source
  originally (the catalog marked them CLI-only / "resolution required"), but each now has an
  explicit, unit-tested emit path; `match_detail` records the concrete live leaf/endpoint:
  - 764 OS-VERSION, 767 BMC-VERSION, 766 EROT-FW-VERSION → gNMI `platform-general/versions/state/`
    `{nos-version,fw-version-bmc,fw-version-erot}` info-metrics (`platform_os/bmc/erot_version_info`).
  - 942 PLR-BW-LOSS-PERCENT → gNMI `interfaces/interface/phy-diag/state/plr-bw-loss-percent`
    (`interface_plr_bw_loss_percent`, percent).
  - 967 FAN-LED → NVUE REST `/nvue_v1/platform/environment` `FAN_STATUS.state` (`fan_led`,
    green/ok=1 else 0).
  - Audit note: an earlier pass token-matched 3 further rows (870 CPU_CORE_NUMBER, 2294
    CABLE-SNR-MEDIA-LANE-N, 2295 CABLE-SNR-HOST-LANE-N) on spurious substrings; on verification no
    lane emits them, so they were re-classified to ABSENT-BLOCKER (see "Notes on blocker rows").
- **IMPLEMENTED** rows are sourced beyond the plain gNMI/NMX-T allowlist:
  - NVUE REST `/nvue_v1/platform/environment/{fan,temperature}` → MAX-SPEED (894); the 21 temp
    `*-CRITICAL/MAX/STATE` rows (`.crit`/`.max`/`.state`) and the 8 `*-TEMP-CURRENT` rows
    (`.current`), emitted per sensor as `platform_temperature{,_max,_critical,_state}` with a `sensor` label.
  - gNMI `platform-general` subscribe path → the 4 memory/disk rows (`886-889`).
  - String rows → `interface_phy_manager_state` (enum-coded), `*_info` info-metrics, and the existing `component_name` label (`ASIC-NAME`).

## Notes on blocker rows

No row is marked "deferred." Every blocker has an explicit escalation disposition:

- **ABSENT-BLOCKER — cable/transceiver leaves (7 rows: 981, 982, 2293, 2296-2299):** the catalog's
  gNMI transceiver-diag path is absent live — the N5400_LD NVLink switch enumerates **no gNMI
  transceiver components** (confirmed live; 64+ active backplane links, so *not* an uncabled rig).
  The 4 fault-flag rows (983-986: CABLE-TX/RX-CDR-LOL, CABLE-TX/RX-LOS) were **re-sourced to NMX-T**
  (live flag families) and are now implemented. The remaining 7 (temp/vcc alarm flags, module
  oper-status, RX/TX power-lane LOW/HIGH thresholds) have no NMX-T or gNMI source; escalate to the
  NVOS gNMI / NMX-T owner re: NVLink cable optical telemetry.
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
- **ABSENT-BLOCKER — CPU_CORE_NUMBER (row 870):** CLI-only (`nv show system cpu`); the catalog
  lists no gNMI/NMX-T source. A prior pass spuriously token-matched the gNMI link knob
  `core-to-phy-link-width-enabled` (a link-width config flag, not a CPU core count); no lane emits
  it. Requires a new CLI collector or NVOS gNMI exposure; escalate to NVOS owner.
- **ABSENT-BLOCKER — CABLE-SNR-MEDIA-LANE-N / CABLE-SNR-HOST-LANE-N (rows 2294, 2295):** catalog
  lists *no source* for either row. NMX-T exposes `rx_power_lane_0/1` (rows 977/978) but **no SNR
  family**; a prior pass spuriously token-matched `rx_power_lane_5`/`cable-proto-cap-ext`. No lane
  emits these. Source-owner follow-up is open (see live-validation runbook step 5) — keep open
  until an NVLink per-lane SNR source is identified or the rows are declared N/A.
