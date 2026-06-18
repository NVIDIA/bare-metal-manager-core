# GB200 NVSWITCH telemetry live-validation runbook

This branch stops before live hardware validation. After build/test/lint review, run the health service locally against one GB200 NVLink Switch BMC endpoint and one switch HOST/NVOS endpoint.

## Collectors that must be enabled

For the GB200 phase, enable all switch telemetry collectors below:

- BMC endpoint (`switch.endpoint_role = "bmc"`):
  - `collectors.sensors` for standard Redfish sensor readings and threshold/range context.
  - `collectors.telemetry_service` for Redfish `TelemetryService/MetricReports/*`.
- HOST endpoint (`switch.endpoint_role = "host"`):
  - `collectors.nmxt` for NMX-T Prometheus telemetry on port `9352`.
  - `collectors.nvue.rest` for existing NVUE health/app/partition/interface diagnostics.
  - `collectors.nvue.gnmi` for SAMPLE telemetry from `components`, `interfaces`, and `platform-general`, plus ON_CHANGE system events.

The BMC proxy ACL must allow:

- `GET /redfish/v1/TelemetryService`
- `GET /redfish/v1/TelemetryService/MetricReportDefinitions/*`
- `GET /redfish/v1/TelemetryService/MetricReports/*`

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

[collectors.telemetry_service]
poll_interval = "1m"
fetch_concurrency = 4
# Empty means all exposed MetricReports. Narrow to ["NvidiaNMMetrics_0"] only if the BMC exposes noisy unrelated reports.
metric_report_ids = []

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

## Local nv-redfish patch command

The infra-controller MR must not commit absolute local paths. For local validation against a locally built `nv-redfish` checkout, use Cargo command-line patching. The local `nv-redfish` workspace package version must satisfy the infra-controller dependency (`0.10.x` for this branch); if the companion checkout is on `origin/main` with a development `0.1.0` workspace version, use a matching release tag or a temporary local-only version edit that is not committed.

```bash
cargo run \
  --config "patch.crates-io.nv-redfish.path=\"${NV_REDFISH_WORKTREE}/redfish\"" \
  -p carbide-health --bin forge-hw-health -- \
  /path/to/gb200-switch-local.toml
```

If the companion `nv-redfish` checkout changes internal crates, add the matching `patch.crates-io` entries documented in `nvswitch_telemetry_nv_redfish_dependency.md`.

## Evidence to capture during live validation

1. `/telemetry` output contains `redfish_telemetry_service` samples for the BMC endpoint.
2. `/telemetry` output contains `switch_nmxt` samples for the HOST endpoint, including any source metric names beyond the three legacy hard-coded metrics.
3. `/telemetry` output contains `nvue_gnmi` samples for:
   - existing canonical interface metrics (`interface_*`), and
   - newly preserved `nvswitch_*` catalog leaf metrics from previously unmapped gNMI leaves.
4. Logs show the TelemetryService, NMX-T, NVUE REST, and NVUE gNMI collectors started for the expected endpoint roles.
5. The two catalog rows with no listed source (`CABLE-SNR-MEDIA-LANE-N`, `CABLE-SNR-HOST-LANE-N`) are checked explicitly in live output. If they do not appear through Redfish MetricReports, NMX-T, or gNMI, open a catalog/source-owner follow-up immediately; keep them open until source-owner resolution.

## Cardinality and series-shape acceptance checks

The branch intentionally preserves generic Redfish MetricReport, NMX-T, and gNMI samples so GB200 bring-up does not drop unknown NVSWITCH rows. Before treating live validation as successful, capture the series shape and confirm it is bounded by device structure rather than by scrape churn:

1. Capture the distinct `(metric name, metric_type, key)` tuples from two consecutive `/telemetry` scrapes after collectors are warm.
2. Confirm the tuple set is stable across those scrapes except for expected hot-plug, link, or error-counter changes.
3. For Redfish MetricReports, confirm labels are limited to report id/URI/definition and metric id/property/identity, and that internal sample keys use escaped raw MetricId/MetricProperty identity so sanitized aliases do not collapse. Raw string values must not appear as metric labels.
4. For NMX-T, confirm unknown metric keys include escaped raw port/source/node identity and stable sorted source-label identity so same metric/port samples with different lane/device labels do not collapse.
5. For gNMI, confirm unknown leaves are keyed by full source path plus endpoint/entity labels and do not create time-varying label names.
6. If live GB200 only needs a subset of TelemetryService reports, narrow `metric_report_ids` and consider tightening the BMC proxy ACL before final merge.

Unit coverage that locks the pre-live behavior:

- Redfish TelemetryService: `metric_report_values_emit_numeric_and_info_samples`.
- NMX-T: `generic_metric_key_includes_sorted_extra_label_identity` and `generic_metric_key_distinguishes_same_port_samples_by_extra_labels`.
- NVUE gNMI: `unmapped_interface_leaf_emits_catalog_metric_sample` and `platform_general_string_leaf_emits_info_metric`.
