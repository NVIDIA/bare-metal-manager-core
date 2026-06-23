# NVSWITCH telemetry nv-redfish dependency notes

> **Superseded (2026-06-18).** The standalone Redfish `TelemetryService` MetricReports
> collector described below was **removed**: live GB200 BMC probes show
> `/redfish/v1/TelemetryService` MetricReports are absent/404, `SwitchMetrics` are
> empty, histograms are empty, and `Ports` are absent. The corrected direction uses
> explicit, catalog-row allowlist mappings over the live BMC sensor/thermal surface
> and the live host NVOS gNMI / NMX-T surfaces. This file is retained for the
> nv-redfish dependency history only; the `telemetry-service` feature, the
> `[collectors.telemetry_service]` config, and the collector itself are no longer
> present in this branch.

Generated during the GB200 NVSWITCH telemetry branch setup.

## Current infra-controller dependency state

- `Cargo.toml` pins `nv-redfish = { version = "0.10.0" }`.
- `Cargo.lock` resolves `nv-redfish`, `nv-redfish-bmc-http`, `nv-redfish-core`, `nv-redfish-schema`, and `nv-redfish-csdl-compiler` to `0.10.0` from crates.io.
- ~~This branch enables `telemetry-service` in `crates/health/Cargo.toml` for the new Redfish TelemetryService collector.~~ (Reverted: the `telemetry-service` feature and collector were removed; see the superseded banner above.)
- The GB200 branch has a local `nv-redfish` worktree available for companion development only:
  - `${NV_REDFISH_WORKTREE}`
  - Branch: `nvswitch_telemetry_gaps`
  - Base: `origin/main` at `dbd2789c987fd320d263d87524fc25fde305bc7f`

## Refreshed upstream state

- Local `${NV_REDFISH_SOURCE_CHECKOUT}` was fetched from `origin` on 2026-06-18.
- Latest observed public tags: `v0.10.2`, `v0.10.1`, `v0.10.0`.
- `v0.10.2` does not appear to contain Fabric/Switch/Port/NVSwitch changes relevant to this work.
- `origin/main` includes a `telemetry-service` feature in `redfish/features.toml`.
- `origin/main` exposes `ServiceRoot::telemetry_service()` behind the `telemetry-service` feature.
- Neither `origin/main` nor `v0.10.2` has a `fabrics` feature or generated/wrapper hits for Fabric, Switch, Port, SwitchMetrics, or PortMetrics in the inspected source.

## Dependency conclusion

Historical note: TelemetryService MetricReports *could* in principle be wired in infra-controller by enabling `telemetry-service` and consuming the typed `TelemetryService` APIs available in nv-redfish 0.10.x. This was attempted and then **reverted** — live GB200 BMC exposes no usable MetricReports, so no TelemetryService collector is wired in this branch.

Redfish Fabric/Switch/Port support needs companion `nv-redfish` work if GB200 live hardware or the catalog requires those paths. The companion work should add standard DMTF schema XMLs and feature entries for Fabric, Switch, Port, SwitchMetrics, PortMetrics, Endpoint, and Zone families, plus ergonomic ServiceRoot/Fabric/Switch navigation wrappers and mock tests.

## Local development strategy

During local development, keep user-local absolute paths out of committed manifests. Use Cargo local patching via command-line `--config` for experiments against the companion `nv-redfish` worktree, for example:

```bash
cargo test -p carbide-health --lib --no-run \
  --config "patch.crates-io.nv-redfish.path=\"${NV_REDFISH_WORKTREE}/redfish\""
```

If companion changes touch internal nv-redfish crates, patch the affected packages too:

```bash
cargo test -p carbide-health --lib --no-run \
  --config "patch.crates-io.nv-redfish.path=\"${NV_REDFISH_WORKTREE}/redfish\"" \
  --config "patch.crates-io.nv-redfish-core.path=\"${NV_REDFISH_WORKTREE}/core\"" \
  --config "patch.crates-io.nv-redfish-schema.path=\"${NV_REDFISH_WORKTREE}/schema\"" \
  --config "patch.crates-io.nv-redfish-csdl-compiler.path=\"${NV_REDFISH_WORKTREE}/csdl-compiler\"" \
  --config "patch.crates-io.nv-redfish-bmc-http.path=\"${NV_REDFISH_WORKTREE}/bmc-http\""
```

## Final MR strategy

Do not commit local absolute path dependencies. Before final review, use one of these acceptable states:

1. A released `nv-redfish` version containing companion support, with `Cargo.toml` and `Cargo.lock` updated accordingly.
2. A reviewer-approved git revision dependency if release timing blocks final integration.
3. A documented split where infra-controller names the required `nv-redfish` companion MR and keeps local path overrides out of the final diff.

## Branch implementation update

~~The GB200 branch consumes the typed TelemetryService API already present in `nv-redfish` 0.10.0 (`ServiceRoot::telemetry_service()`, `TelemetryService::metric_report_links()`, and `MetricReportLink::fetch()`).~~ **Reverted.** The branch no longer consumes the TelemetryService API; the collector was removed after live GB200 probes returned no MetricReports. No local `nv-redfish` path dependency is committed.

Direct Fabric/Switch/Port wrappers are still absent from `nv-redfish` 0.10.x and `origin/main` as inspected. BMC-side switch telemetry is now sourced from the live BMC sensor/thermal surface (not TelemetryService MetricReports), with the local companion worktree kept available if live GB200 evidence later proves a required metric is only available from Fabric/Switch/Port resources and not from the BMC sensor surface, NMX-T, or gNMI.
