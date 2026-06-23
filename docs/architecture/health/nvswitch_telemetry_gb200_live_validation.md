# GB200 NVSWITCH telemetry live-validation runbook

> **Implementation note.** GB200 telemetry is collected via **explicit catalog-row
> allowlists** over the live host surfaces: NMX-T (`switch_nmxt`), NVOS gNMI
> (`nvue_gnmi`, explicit per-leaf), NVUE REST (`fan_max_speed` from
> `/platform/environment/fan`), and standard Redfish sensors (`hw_sensor`). There is
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
  - `collectors.nvue.rest` for NVUE health/app/partition/interface diagnostics and `fan_max_speed` from `/platform/environment/fan`.
  - `collectors.nvue.gnmi` for SAMPLE telemetry from `components`, `interfaces`, and `platform-general` (memory/disk), plus ON_CHANGE system events.

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
3. `/telemetry` output contains `nvue_gnmi` samples for the HOST endpoint: canonical `interface_*` (incl. `interface_link_speed_active` in gbps), `component_*`, and `platform_memory_used/total` + `platform_disk_total/used`.
4. `/telemetry` output contains the NVUE REST `fan_max_speed` sample (HOST). Logs show the NMX-T, NVUE REST, and NVUE gNMI collectors started for the expected roles; matched-but-uncoercible leaves are debug-logged, not emitted.
5. The two catalog rows with no listed source (`CABLE-SNR-MEDIA-LANE-N`, `CABLE-SNR-HOST-LANE-N`) are checked explicitly in live output. If they do not appear through Redfish MetricReports, NMX-T, or gNMI, open a catalog/source-owner follow-up immediately; keep them open until source-owner resolution.

## Series-shape acceptance checks

Only explicit catalog-row mappings are emitted; unknown sources are dropped (debug-logged), never sanitized into metrics. Before treating live validation as successful:

1. Capture the distinct `(name, metric_type, key)` tuples from two consecutive `/telemetry` scrapes after collectors are warm.
2. Confirm the tuple set is stable across scrapes except for expected link/error-counter changes.
3. Confirm every emitted series is one of the known families: `hw_sensor`, `switch_nmxt`, `nvue_gnmi` (`interface_*`/`component_*`/`platform_*`), or `fan_max_speed`. No `nvswitch_*`, `source_metric`, or `redfish_telemetry_service` series may appear.
4. Confirm NMX-T identity labels are the allowlisted `NMXT_LABEL_MAP` set (bounded per port); no raw/unknown source names as labels.

Unit coverage that locks this behavior:

- NMX-T: `test_nmxt_metric_map_locks_type_and_unit`, `test_unknown_nmxt_sources_not_allowlisted`.
- NVUE gNMI: `test_interface_link_speed_active_gbps`, `test_platform_general_numeric_leaf_mappings`, `test_platform_general_string_leaf_is_not_exported` (string leaves emit nothing).
- NVUE REST: `test_fan_max_speed_emit`.

## Blocker escalations (Stage 0)

Stage 0 live probe (2026-06-20) classified all 193 GB200-applicable NVSWITCH catalog rows.
34 rows are escalated below (21 config-threshold, 13 absent-from-live-probe). No
row is deferred — each has an explicit disposition and a named resolution path.

### Group A — Config-threshold rows (21 rows, BLOCKER-THRESHOLD)

These catalog entries represent threshold/limit/alarm-state values configured on the device, not
streamed telemetry counters. They are not exposed as live gNMI leaves and cannot be implemented
without a new data source.

**Resolution:** Source owner (NVOS gNMI / Redfish sensor threshold team) must confirm whether
a future gNMI path or Redfish sensor `ThresholdHigh`/`ThresholdLow`/`ReadingRangeMax` field
can expose these. Until confirmed, they are out-of-scope for this branch.

| Row  | Metric                  |
|------|-------------------------|
| 872  | ASIC-TEMP-CRITICAL      |
| 873  | ASIC-TEMP-MAX           |
| 874  | ASIC-TEMP-STATE         |
| 879  | AMBIENT-MNG-TEMP-STATE  |
| 881  | CPU_PACK_TEMP_CRITICAL  |
| 882  | CPU_PACK_TEMP_MAX       |
| 883  | CPU_PACK_TEMP_STATE     |
| 890  | SODIMM_TEMP_CRITICAL    |
| 891  | SODIMM_TEMP_MAX         |
| 892  | SODIMM_TEMP_STATE       |
| 1241 | DRIVE-TEMP-CRITICAL     |
| 1242 | DRIVE-TEMP-MAX          |
| 1243 | DRIVE-TEMP-STATE        |
| 1245 | HSC-VINDC-TEMP-CRITICAL |
| 1246 | HSC-VINDC-TEMP-MAX      |
| 1247 | HSC-VINDC-TEMP-STATE    |
| 1249 | PDB-CONV-TEMP-CRITICAL  |
| 1251 | PDB-CONV-TEMP-STATE     |
| 1253 | PMIC-TEMP-CRITICAL      |
| 1255 | PMIC-TEMP-STATE         |
| 1259 | SWB-ASIC-PCB-TEMP-STATE |

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
