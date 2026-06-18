# NVSWITCH telemetry nv-redfish dependency notes

Generated during the GB200 NVSWITCH telemetry branch setup.

## Current infra-controller dependency state

- `Cargo.toml` pins `nv-redfish = { version = "0.10.0" }`.
- `crates/health/Cargo.toml` enables standard health features but not `telemetry-service`.
- The GB200 branch uses a local `nv-redfish` worktree for development only:
  - `/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps`
  - Branch: `nvswitch_telemetry_gaps`
  - Base: `origin/main` at `dbd2789c987fd320d263d87524fc25fde305bc7f`

## Refreshed upstream state

- Local `/Users/mkoci/Projects/nv-redfish` was fetched from `origin` on 2026-06-18.
- Latest observed public tags: `v0.10.2`, `v0.10.1`, `v0.10.0`.
- `origin/main` includes a `telemetry-service` feature in `redfish/features.toml`.
- `origin/main` exposes `ServiceRoot::telemetry_service()` behind the `telemetry-service` feature.
- Neither `origin/main` nor `v0.10.2` has a `fabrics` feature or generated/wrapper hits for Fabric, Switch, Port, SwitchMetrics, or PortMetrics in the inspected source.

## Dependency conclusion

TelemetryService MetricReports can be wired by enabling `telemetry-service` and updating `crates/health` to consume the typed `TelemetryService` APIs.

Redfish Fabric/Switch/Port support needs companion `nv-redfish` work if GB200 live hardware or the catalog requires those paths. The companion work should add standard DMTF schema XMLs and feature entries for Fabric, Switch, Port, SwitchMetrics, PortMetrics, Endpoint, and Zone families, plus ergonomic ServiceRoot/Fabric/Switch navigation wrappers and mock tests.

## Local development strategy

During local development, use the `nv-redfish` worktree as a path dependency or patch only on the GB200 feature branch. Do not leave a user-local absolute path in the final MR. Before final review, replace local path usage with one of:

1. A released `nv-redfish` version containing the companion support.
2. A reviewer-approved git revision dependency if release timing blocks final integration.
3. A documented two-MR handoff where the infra-controller MR names the required `nv-redfish` companion MR and keeps local-path changes out of the final diff.

Because upstream source manifests use workspace version `0.1.0` while crates.io currently publishes `0.10.x`, local path development should use an explicit path dependency in the workspace dependency table rather than relying on the crates.io version constraint.
