# NVSWITCH telemetry GB200 source matrix

Generated from sanitized Telemetry Catalog extraction artifacts for rows where `Device (CompClass)` is NVSWITCH and one of the GB200 columns is `Yes`:

- `Applicable for GB200 NVL HMC`
- `Applicable for GB200 NVL BMC`
- `Applicable for GB200 NVL NvswitchTray`

CSV matrix: `docs/architecture/health/nvswitch_telemetry_gb200_matrix.csv`

## Counts

- Total GB200-applicable NVSWITCH rows: 193

### Implementation status

- already-covered-regression-required: 5
- covered-by-generic-infra-requires-live-validation: 150
- requires-live-source-equivalent: 36
- requires-live-source-resolution: 2

### Branch coverage status

- covered_generic_infra_unvalidated: 150
- covered_host_gnmi: 4
- covered_host_nmxt: 1
- source_equivalent_required: 36
- source_resolution_required: 2

### Primary source

- NMX-T: 57
- NVOS CLI: 36
- NVOS gNMI: 97
- Redfish Fabric/Switch/Port: 1
- SOURCE UNLISTED live source resolution: 2

## GB200 branch implementation coverage

The `nvswitch_telemetry_gaps` branch implements common GB+VR-friendly collector infrastructure for the GB200 phase:

- Redfish BMC: enabled `nv-redfish` `telemetry-service`, added a switch-BMC-only TelemetryService collector, and emits every numeric/boolean/string `MetricReport` value as `redfish_telemetry_service` samples with report and source-property labels.
- BMC proxy: widened TelemetryService ACLs to `MetricReportDefinitions/*` and `MetricReports/*` so live GB200 validation is not limited to `NvidiaNMMetrics_0`.
- NMX-T HOST: preserves all numeric Prometheus samples instead of dropping unknown metric names; legacy `Effective_BER`, `Symbol_Errors`, and `Link_Down` metric names remain canonical.
- NVUE gNMI HOST: subscribes to `components`, `interfaces`, and `platform-general`; known current metrics keep their existing names, and previously unmapped leaves are emitted as source-qualified `nvswitch_*` samples.
- Config: `collectors.telemetry_service` is disabled by default, and `collectors.nvue.gnmi.paths.platform_general_enabled` is an explicit opt-in path gate; the example and live-validation configs enable the full GB200 switch collector set.

The generic-preservation surfaces are behavior-locked by unit tests before live hardware validation:

- Redfish TelemetryService: `metric_report_values_emit_numeric_and_info_samples` covers numeric, string/info, and boolean/state MetricReport values.
- NMX-T: `generic_metric_key_includes_sorted_extra_label_identity` and `generic_metric_key_distinguishes_same_port_samples_by_extra_labels` cover stable key identity for unknown Prometheus samples with extra labels.
- NVUE gNMI: `unmapped_interface_leaf_emits_catalog_metric_sample` and `platform_general_string_leaf_emits_info_metric` cover previously unmapped interface leaves and platform-general string leaves.

Rows that still have no catalog-listed source remain in scope: `CABLE-SNR-MEDIA-LANE-N` and `CABLE-SNR-HOST-LANE-N` are marked `requires-live-source-resolution` and must be checked during live validation. The generic Redfish MetricReport, NMX-T, and gNMI preservation paths will expose them if the device emits them; if not, open a source-owner follow-up immediately.

## Execution rules

- Every row must keep `primary_source`, `fallback_source`, `source_precedence`, and `duplicate_alias_policy` populated before implementation is marked complete.
- Default duplicate policy is one canonical series per catalog row; source-qualified duplicates require source-path proof and consumer-safety rationale.
- Generic-preserved metrics must keep bounded identity labels: report id/URI/definition and metric id/property/identity for Redfish MetricReports, raw source metric plus sorted source-label identity for NMX-T, and full gNMI path plus endpoint/entity labels for gNMI. Redfish internal keys must use escaped raw MetricId/MetricProperty identity, and NMX-T generic keys must escape raw port/source/node/label identity, to avoid aliasing. Raw string metric values must not be emitted as labels.
- Rows marked `requires-live-source-resolution` or `requires-live-source-equivalent` remain in scope; they require live source proof or immediate escalation before GB200 signoff.
- Live GB200 validation happens after the branch is built, tested, linted, pushed, and reviewed.
