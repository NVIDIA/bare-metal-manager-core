# GB200 NVSWITCH telemetry live-validation runbook

> **Implementation note.** GB200 telemetry is collected via **explicit catalog-row
> allowlists** over the live host surfaces: NMX-T (`switch_nmxt`), NVOS gNMI
> (`nvue_gnmi`, explicit per-leaf), NVUE REST (`fan_max_speed` from
> `/platform/environment/fan`, `fan_led` from `/platform/environment`), and standard
> Redfish sensors (`hw_sensor`). There is
> **no** standalone Redfish `TelemetryService` collector and **no** generic/sanitized
> source preservation — both were evaluated against the live GB200 BMC and removed.
> Unknown gNMI/NMX-T sources are dropped and debug-logged, never emitted. nv-redfish is
> consumed at the released `0.10.0` (no local patch).

This branch stops before live hardware validation. After build/test/lint review, run the health service locally against one GB200 NVLink Switch BMC endpoint and one switch HOST/NVOS endpoint.

## Collectors that must be enabled

For the GB200 phase, enable all switch telemetry collectors below:

- BMC endpoint (`switch.endpoint_role = "bmc"`):
  - `collectors.sensors` for standard Redfish sensor readings and threshold/range context (the temp/thermal `hw_sensor` series plus `*_range_max`/`*_range_min`).
- HOST endpoint (`switch.endpoint_role = "host"`):
  - `collectors.nmxt` for NMX-T Prometheus telemetry on port `9352`.
  - `collectors.nvue.rest` for NVUE health/app/partition/interface diagnostics, `fan_max_speed` from `/platform/environment/fan`, and `fan_led` (aggregate `FAN_STATUS`) from `/platform/environment`.
  - `collectors.nvue.gnmi` for SAMPLE telemetry from `components`, `interfaces`, and `platform-general` (memory/disk via `/state`, OS/BMC/EROT firmware versions via `/versions`), plus ON_CHANGE system events.

No TelemetryService proxy ACL changes are required — collection uses the standard Redfish sensor paths plus the host NMX-T/gNMI/NVUE endpoints.

## Local static config template

Replace placeholders after the branch is reviewed. Keep real credentials out of git.

```toml
[endpoint_sources.carbide_api]
enabled = false

[sinks.health_report]
enabled = false

[sinks.rack_health_report]
enabled = false

[sinks.switch_health_report]
enabled = false

[sinks.power_shelf_health_report]
enabled = false

[sinks.prometheus]
enabled = true

[metrics]
endpoint = "127.0.0.1:9009"
prefix = "carbide_hardware_health"

[[endpoint_sources.static_bmc_endpoints]]
ip = "<GB200_SWITCH_BMC_IP>"
port = 443
mac = "<GB200_SWITCH_BMC_MAC>"
username = "<BMC_USERNAME>"
password = "<BMC_PASSWORD>"
switch = { serial = "<SWITCH_SERIAL>", endpoint_role = "bmc", slot_number = <SLOT>, tray_index = <TRAY> }

[[endpoint_sources.static_bmc_endpoints]]
ip = "<GB200_SWITCH_HOST_IP>"
port = 443
mac = "<GB200_SWITCH_HOST_MAC>"
username = "<NVOS_USERNAME>"
password = "<NVOS_PASSWORD>"
switch = { serial = "<SWITCH_SERIAL>", endpoint_role = "host", is_primary = true, nmxt_enabled = true, slot_number = <SLOT>, tray_index = <TRAY> }

[collectors.discovery]
refresh_interval = "5m"
discovery_concurrency = 4

[collectors.sensors]
sensor_fetch_interval = "1m"
sensor_fetch_concurrency = 8
include_sensor_thresholds = true

[collectors.metrics]
enabled = false

[collectors.logs]
enabled = false

[collectors.firmware]
enabled = false

[collectors.leak_detector]
enabled = false

[collectors.nmxt]
scrape_interval = "1m"
request_timeout = "30s"

[collectors.nvue.rest]
poll_interval = "1m"
request_timeout = "30s"

[collectors.nvue.rest.paths]
system_health_enabled = true
cluster_apps_enabled = true
sdn_partitions_enabled = true
interfaces_enabled = true
platform_environment_fan_enabled = true  # MAX-SPEED via /nvue_v1/platform/environment/fan

[collectors.nvue.gnmi]
gnmi_port = 9339
sample_interval = "1m"
request_timeout = "30s"
system_events_enabled = true

[collectors.nvue.gnmi.paths]
components_enabled = true
interfaces_enabled = true
platform_general_enabled = true
```

## Run the local health service

nv-redfish is consumed at the released `0.10.0` — no local patch or companion checkout is needed.

```bash
cargo run -p carbide-health --bin forge-hw-health -- /path/to/gb200-switch-local.toml
```

## Evidence to capture during live validation

1. `/telemetry` output contains `hw_sensor` samples for the BMC endpoint (temp/thermal readings; plus `*_range_max`/`*_range_min` where the sensor exposes ranges).
2. `/telemetry` output contains `switch_nmxt` samples for the HOST endpoint — only the explicit `NMXT_METRIC_MAP` families with the allowlisted identity labels (no sanitized/unknown source names).
3. `/telemetry` output contains `nvue_gnmi` samples for the HOST endpoint: canonical `interface_*` (incl. `interface_link_speed_active` in gbps and `interface_plr_bw_loss_percent`), `component_*`, `platform_memory_used/total` + `platform_disk_total/used`, and the switch-level `platform_{os,bmc,erot}_version_info` info-metrics (value 1.0, version carried in the label).
4. `/telemetry` output contains the NVUE REST `fan_max_speed` and `fan_led` samples (HOST). Logs show the NMX-T, NVUE REST, and NVUE gNMI collectors started for the expected roles; matched-but-uncoercible leaves are debug-logged, not emitted.
5. The two catalog rows with no listed source (`CABLE-SNR-MEDIA-LANE-N` row 2294, `CABLE-SNR-HOST-LANE-N` row 2295) are checked explicitly in live output. NMX-T exposes `rx_power_lane_0/1` (rows 977/978) but **no SNR family**, so neither row is emitted today (an earlier rescue pass spuriously token-matched `rx_power_lane_5`/`cable-proto-cap-ext` — corrected to ABSENT-BLOCKER). If they do not appear through Redfish MetricReports, NMX-T, or gNMI, open a catalog/source-owner follow-up immediately; keep them open until source-owner resolution.

## Series-shape acceptance checks

Only explicit catalog-row mappings are emitted; unknown sources are dropped (debug-logged), never sanitized into metrics. Before treating live validation as successful:

1. Capture the distinct `(name, metric_type, key)` tuples from two consecutive `/telemetry` scrapes after collectors are warm.
2. Confirm the tuple set is stable across scrapes except for expected link/error-counter changes.
3. Confirm every emitted series is one of the known families: `hw_sensor`, `switch_nmxt`, `nvue_gnmi` (`interface_*`/`component_*`/`platform_*`, incl. `platform_{os,bmc,erot}_version_info`), `fan_max_speed`, or `fan_led`. No `nvswitch_*`, `source_metric`, or `redfish_telemetry_service` series may appear.
4. Confirm NMX-T identity labels are the allowlisted `NMXT_LABEL_MAP` set (bounded per port); no raw/unknown source names as labels.

Unit coverage that locks this behavior:

- NMX-T: `test_nmxt_metric_map_locks_type_and_unit`, `test_unknown_nmxt_sources_not_allowlisted`.
- NVUE gNMI: `test_interface_link_speed_active_gbps`, `test_platform_general_numeric_leaf_mappings`, `test_platform_general_string_leaf_is_not_exported` (string leaves emit nothing), `test_interface_numeric_leaf_table_mappings` (locks `interface_plr_bw_loss_percent` type/unit), `test_platform_general_version_info_metrics` + `test_platform_general_empty_version_string_is_not_exported` (OS/BMC/EROT version info-metrics), `test_nvue_subscribe_paths_all_enabled` (the `/platform-general/versions` subscribe path is added).
- NVUE REST: `test_fan_max_speed_emit`, `test_fan_led_emit` (green/ok=1, amber=0, absent FAN_STATUS emits nothing) + `test_parse_platform_environment_fan_status`.

## Blocker escalations (Stage 0)

Stage 0 live probe (2026-06-20) classified all 193 GB200-applicable NVSWITCH catalog rows.
**16 rows remain ABSENT-BLOCKER** (no live source on this platform) — these are the escalations
in Groups B–D plus the rescue-match audit below. No row is deferred — each has an explicit
disposition and a named resolution path.

The remaining subsections here (temperature, string-valued, and firmware/PLR/fan-LED, all marked
**RESOLVED**) are *not* escalations; they are kept for provenance, recording rows that earlier
passes had escalated but that are now implemented, so the trail from the Stage-0 blocker set down
to the final 16 is auditable. A post-implementation audit on 2026-06-23 moved 3 rows *into* the
blocker set — 870 CPU_CORE_NUMBER, 2294/2295 CABLE-SNR-MEDIA/HOST-LANE-N — that an earlier pass
had token-matched but no lane actually emits (see "Rescue-match audit" below).

### Temperature threshold rows — RESOLVED (21 rows, formerly BLOCKER-THRESHOLD)

The 21 temperature `*-CRITICAL` / `*-MAX` / `*-STATE` rows (ASIC / CPU-Pack / SODIMM / Drive /
HSC-VinDC / PDB-Conv / PMIC / SWB-ASIC-PCB / Ambient-MNG) are now implemented from NVUE REST
`/nvue_v1/platform/environment/temperature` (`.crit` / `.max` / `.state` per sensor; only the fields
a sensor actually exposes are emitted). The 8 `*-TEMP-CURRENT` rows were re-sourced from `.current`
on the same endpoint, correcting an earlier spurious gNMI token match. No longer escalated.

### Group B — Cable/transceiver leaves (7 rows, ABSENT-BLOCKER)

**Root cause (NOT an uncabled rig).** The N5400_LD NVLink switch enumerates **no gNMI transceiver
components** — the live component tree has only `ASIC`/`CPU`/`FAN`/`SWITCH` types and no
`/components/component/transceiver/*` subtree, even though 64+ ports are active NDR/XDR backplane
links (re-probed live 2026-06-23). The catalog mapped these rows to an openconfig transceiver-diag
path this platform does not expose; NVLink backplane cables are not modeled as openconfig
transceivers.

**Re-sourced to NMX-T (now implemented):** 4 fault-flag rows have live NMX-T families (value 0 = no
fault on the active links) and were moved into `NMXT_METRIC_MAP` — 983 CABLE-TX-CDR-LOL
(`tx_cdr_lol`), 984 CABLE-RX-CDR-LOL (`rx_cdr_lol`), 985 CABLE-TX-LOS (`tx_los`), 986 CABLE-RX-LOS
(`rx_los`). They are no longer blockers.

**Resolution (remaining 7):** no NMX-T or gNMI source exists for the alarm/threshold/oper-status
rows below. Escalate to the NVOS gNMI / NMX-T owner: is there any source (gNMI/NMX-T/Redfish/CLI)
for NVLink cable optical alarms, module oper-status, and per-lane power thresholds on N5400_LD, or
are these rows N/A for NVLink backplane switches?

| Row  | Metric                              | Catalog source (absent live)                                  |
|------|-------------------------------------|----------------------------------------------------------------|
| 981  | CABLE-TEMP-ALARM                    | gNMI transceiver `temp-high-alarm-flag` (no transceiver component) |
| 982  | CABLE-VOLTAGE-ALARM                 | gNMI transceiver `vcc-high-alarm-flag` (no transceiver component)  |
| 2293 | CABLE-OPER-STATUS                   | gNMI transceiver `module-oper-status` (no transceiver component)   |
| 2296 | NVSWITCH-CABLE-RX-POWER-LANE-LOW-N  | gNMI transceiver thresholds `input-power-lower` (absent)           |
| 2297 | NVSWITCH-CABLE-TX-POWER-LANE-LOW-N  | gNMI transceiver thresholds `output-power-lower` (absent)          |
| 2298 | NVSWITCH-CABLE-RX-POWER-LANE-HIGH-N | gNMI transceiver thresholds `input-power-upper` (absent)           |
| 2299 | NVSWITCH-CABLE-TX-POWER-LANE-HIGH-N | gNMI transceiver thresholds `output-power-upper` (absent)          |

### Group C — NMX-T RDMA queue counters (3 rows, ABSENT-BLOCKER)

NMX-T fields were not present in the live scrape output. These are RDMA queue error counters
that may only appear under active RDMA workloads or specific firmware versions.

**Resolution:** Escalate to NMX-T / RDMA owner with the NMX-T version from the test rig.
Re-probe under active RDMA traffic if possible.

| Row  | Metric      | NMX-T field not live |
|------|-------------|----------------------|
| 1706 | RQ-NUM-WRFE | `rq_num_wrfe`        |
| 1707 | RQ-NUM-LLE  | `rq_num_lle`         |
| 1708 | SQ-NUM-WRFE | `sq_num_wrfe`        |

### Group D — Single-field ABSENT-BLOCKERs

**OS-KERNEL (row 765):** Catalog source is NVOS CLI only (`nv show system version {build-id}`).
No gNMI leaf or NMX-T field matched. Implementing this row requires either a new CLI collector
(not in scope for this branch) or a new NVOS gNMI exposure. Escalate to NVOS owner.

**TIME-SINCE-LASTS-CLEAR (row 909):** gNMI leaf
`/interfaces/interface/phy-diag/state/time-since-last-clear-min` is in the NVOS schema but
returned no data. Escalate to NVOS gNMI owner with NVOS version; confirm whether this leaf
requires a specific counter-clear event to populate.

**PLR-CODES-LOSS (row 931):** NMX-T field `HiRetransmissionRate` is not present in the live
scrape. This may be a naming discrepancy or a field absent in the installed NMX-T version.
Escalate to NMX-T owner with the NMX-T version string from the test rig.

### String-valued rows — RESOLVED (6 rows, now implemented)

These 6 catalog rows are string-valued and were previously escalated; they are now implemented:
- `961 PHY-MANAGER-STATE` — enum-coded to `interface_phy_manager_state` (active/linkup = 1, else 0).
- `965 VL-CAPABILITIES`, `862 CONTACT`, `863 LOCATION`, `864 NODE-DESCRIPTION` — emitted as
  info-metrics (value 1 with the string carried in a label; skipped when empty, so `CONTACT`/`LOCATION`
  emit only when configured).
- `876 ASIC-NAME` — covered by the existing `component_name` label on every component metric (not re-emitted).

### Firmware-version / PLR / fan-LED rows — RESOLVED (5 rows, now implemented)

These 5 catalog rows were previously rescue-matched by token but not emitted by any lane; each
now has an explicit, unit-tested emit path:
- `764 OS-VERSION`, `767 BMC-VERSION`, `766 EROT-FW-VERSION` — gNMI now also subscribes
  `/platform-general/versions` (sibling of `/state`); the `versions/state/{nos-version,
  fw-version-bmc,fw-version-erot}` leaves emit switch-level info-metrics
  `platform_{os,bmc,erot}_version_info` (value 1.0, raw version carried in the
  `{os,bmc,erot}_version` label; empty strings emit nothing).
- `942 PLR-BW-LOSS-PERCENT` — gNMI `interfaces/interface/phy-diag/state/plr-bw-loss-percent`
  added to the numeric interface-leaf allowlist as `interface_plr_bw_loss_percent` (unit `percent`).
- `967 FAN-LED` — re-sourced from NVUE REST: the `/nvue_v1/platform/environment` parent summary's
  aggregate `FAN_STATUS.state` LED is emitted as switch-level `fan_led` (green/ok = 1.0, any other
  state = 0.0, absent = nothing), gated on `platform_environment_status_enabled` (default true).
  The catalog's CLI LED path (`nv show platform environment led`) is not used.

### Rescue-match audit — 3 rows re-classified to ABSENT-BLOCKER (2026-06-23)

A verification pass over the 8 `RESOLVED-LIVE` rows found 3 that an earlier token-rescue had marked
`implemented` but that **no collector lane actually emits**. They are now ABSENT-BLOCKER:
- **`870 CPU_CORE_NUMBER`** — catalog source is NVOS CLI only (`nv show system cpu`). The rescue
  token `core-to-phy-link-width-enabled` is a gNMI link-width *config knob*, not a CPU core count.
  No gNMI/NMX-T emit arm exists. Resolution: new CLI collector or NVOS gNMI exposure; escalate to
  NVOS owner (same path as `765 OS-KERNEL`).
- **`2294 CABLE-SNR-MEDIA-LANE-N` / `2295 CABLE-SNR-HOST-LANE-N`** — catalog lists no source. NMX-T
  has `rx_power_lane_0/1` (power, rows 977/978) but no per-lane **SNR** family; the rescue tokens
  (`rx_power_lane_5`, `cable-proto-cap-ext`) do not exist as live SNR sources. No emit arm exists.
  Resolution: source-owner follow-up (see "Evidence to capture" step 5); keep open until an NVLink
  per-lane SNR source is identified or the rows are declared N/A for NVLink backplane switches.
