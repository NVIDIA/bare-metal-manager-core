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
- NVUE gNMI: `test_interface_link_speed_active_gbps`, `test_platform_general_numeric_leaf_mappings`, `test_platform_general_unmapped_string_leaf_is_not_exported` (unmapped string leaves emit nothing), `test_interface_numeric_leaf_table_mappings` (locks `interface_plr_bw_loss_percent` type/unit), `test_platform_general_version_info_metrics` + `test_platform_general_empty_version_string_is_not_exported` (OS/BMC/EROT version info-metrics), `test_nvue_subscribe_paths_all_enabled` (the `/platform-general/versions` subscribe path is added). StateSet shape (per-state 0/1 series with a `state` label, unit `state`): `test_interface_oper_status_state_set`, `test_interface_physical_port_state_enum` (polling/training => up=0/down=1), `test_interface_logical_port_state_enum`, `test_interface_phy_manager_state_enum` + `test_phy_manager_to_state_helper` (Inactive/Deactivated => up=0/down=1 substring regression), `test_component_oper_status_shared_leaf_fan_and_cpu`, `test_component_health_status_state_set` (unrecognized => unknown=1).
- NVUE REST: `test_fan_max_speed_emit`, `test_fan_led_emit` (StateSet: green/ok => ok=1, amber => not_ok=1, absent FAN_STATUS emits nothing) + `test_parse_platform_environment_fan_status`. StateSet shape also locked by `test_system_health_mapping`, `test_partition_health_mapping`, `test_app_status_mapping`, `test_temp_state_to_state_mapping`, `test_fan_led_to_state_mapping`, and `test_platform_temperature_emit` (absent sensor `state` emits no StateSet).

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
- `961 PHY-MANAGER-STATE` — emitted as a StateSet `interface_phy_manager_state` (one 0/1 series per
  state with a `state` label; `up` when an `active`/`linkup` token matches on a word boundary, else
  `down`).
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
  aggregate `FAN_STATUS.state` LED is emitted as switch-level `fan_led`, a StateSet (per-state 0/1
  series with a `state` label: green/ok => `ok`, any other state => `not_ok`; absent = nothing),
  gated on `platform_environment_status_enabled` (default true).
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

## NMX-T field representation validation (DEFERRED — requires live GB200 rig)

These NMX-T fields had their representation changed during review (label → metric / StateSet, or
per-sink routing). The chosen representations are **derived from source/catalog analysis, not yet
confirmed on live hardware**, and must be validated on a real GB200 NVLink switch before merge is
considered fully signed off.

**Why this needs live verification (critical caveat).** The target firmware NVOS **25.02.2553**
ships **NMX-T 1.3.4**, which **predates** the NMX-T Prometheus metric-vs-label renderer fix
(**NVBug 6131830**, fixed in NMX-T 4.20.4 / 4.21.4 / 5.06.12, telemetry commit `3dd5d388`). On the
pre-fix renderer, `/xcset/nvlink_domain_telemetry` may render the same field as a string label on
one endpoint and a numeric gauge on another (`/metrics`), or render empty — and a `;lookup=` xcset
suffix can flip string↔numeric. So the *actual* on-wire form of these fields on 25.02.2553 must be
captured, not assumed. Our scraper is robust to either form (unmapped strings fall back to
`unknown` / are dropped, never fabricated), so collection is safe regardless — but the
representation decisions below should be re-confirmed against reality.

### Capture commands (run on / against the live switch host)

```bash
# What NMX-T actually renders for the fields in question, on BOTH endpoints:
curl -s http://<switch>:9352/metrics                       | grep -E 'local_reason_opcode|remote_reason_opcode|down_blame|fec_mode_active|Active_FEC|Module_Temperature|Status_Message'
curl -s http://<switch>:9352/xcset/nvlink_domain_telemetry | grep -E 'local_reason_opcode|remote_reason_opcode|down_blame|Active_FEC|Module_Temperature|Status_Message' | head
curl -s http://<switch>:9352/management/xcset/nvlink_domain_telemetry | head
curl -s 'http://<switch>:9352/management/schema?schema_id=all' > nmxt-schema.json   # value-space / lookup tables
# Distinct observed values per field (empirical floor for the value space):
curl -s http://<switch>:9352/xcset/nvlink_domain_telemetry \
  | grep -oE '(down_blame|local_reason_opcode|remote_reason_opcode|Active_FEC|Status_Message|Module_Temperature)="[^"]*"' \
  | sort -u
```

Source-of-truth references for the value spaces (use to confirm closed-enum membership):
NVOS `nvos/src/nvos-swss/orchagent/portsorch.h` (link-down reason opcode map `0..49`, read from
SAI `SAI_PORT_ATTR_LINK_DOWN_{LOCAL,REMOTE}_REASON`); `Telemetry_Catalog_v4.0_Telemetry_APIs.csv`;
NMX-T producer `gitlab-master.nvidia.com/telemetry/nmx-telemetry`.

### Per-field acceptance checks

1. **`cable_temperature_celsius`** (was `cable_temp` label → numeric gauge, one series/port). Confirm
   the `Module_Temperature` label is present in the scrape; confirm our exporter emits exactly one
   `cable_temperature_celsius` series per port with the parsed value (e.g. `"37C"→37`). On a rig with
   **optical** modules (not just the passive backplane, which reads `0C`), confirm the value varies
   over time **and** that no `cable_temp` *label* reappears (the churn fix). 
2. **`down_blame`** (was label → StateSet `unknown`/`local_phy`/`remote_phy`). Confirm the live
   string values are within that closed set; any value mapping to `unknown` that *isn't* literally
   "Unknown" is an unmapped source token → record it and extend the mapping. Confirm exactly 3
   series per port, exactly one `=1`. Best signal: induce/observe a link-down and confirm the active
   state flips (`local_phy`/`remote_phy`).
3. **`status_message`** (kept as label, **Prometheus-excluded, OTLP-only**). Confirm it is **absent**
   from our Prometheus `/telemetry` scrape and **present** as a data-point attribute in the OTLP
   export. Capture the distinct-value count over a soak window to confirm it is bounded (a finite
   decode of the opcode table), not unbounded free text. If it proves unbounded/noisy in OTLP,
   reconsider dropping or moving to the events/logs path.
4. **`local_reason_opcode` vs `remote_reason_opcode`** (left as-is: local = string label, remote =
   numeric `code` metric). Confirm on 25.02.2553 which form each actually renders. If **both** render
   numeric (post-fix backport) — or if `nmxt-schema.json` exposes a stable numeric↔string map — then
   numeric-ifying `local_reason_opcode` into a `code` metric (consistent with `remote_reason_opcode`)
   becomes worthwhile. Until then the local=string/remote=numeric asymmetry is a documented NMX-T
   1.3.4 source artifact, **not** our bug — do NOT hardcode a `0..49` reverse map (it differs across
   versions, e.g. `0..37` in older customer docs).
5. **`fec_mode_active` (`Active_FEC`)** (left as a label). Capture distinct values incl. aliases
   (`Int_KP4_FEC_PLR` etc. vs the catalog canonical set `No_FEC` / `Firecode_FEC` / `Standard_RS_FEC`
   / `Standard_LL_RS_FEC` / `Interleaved_Standard_RS-FEC` / `Standard_RS-FEC`). Only convert to a
   StateSet if the alias→canonical normalization map can be sourced authoritatively; otherwise the
   low-churn label is fine.

### Cardinality observation (do this while validating)

Scrape our `/telemetry` endpoint twice ~1 minute apart after collectors are warm; diff the distinct
`(metric_type, label-set)` tuples. Expectation: stable except expected counter movement. Then induce
a link event and re-diff — confirm the only new series are the intended StateSet flips
(`down_blame`, port/oper state), **not** a fan-out of new label-value combinations. Record per-field
distinct-value counts so future representation decisions have an empirical basis.

### Follow-on goal (AFTER live validation): representation true-up

Once the live-hardware validation above is complete, perform a deliberate **true-up** pass over the
full NVSWITCH catalog coverage to confirm we are filling the gaps in the *best* way, not merely a
working way:
- Re-confirm each chosen source and representation against observed live data.
- Revisit label-vs-metric-vs-StateSet decisions with **real cardinality numbers** (not estimates).
- Re-examine the 16 ABSENT-BLOCKER rows for newly-available sources — especially cable optical
  telemetry, the RDMA queue counters under active load, OS-KERNEL, and TIME-SINCE-LAST-CLEAR.
- Reconcile the matrix to reality.

This is sequenced strictly **after** hardware validation: validate what we built, then optimize.
