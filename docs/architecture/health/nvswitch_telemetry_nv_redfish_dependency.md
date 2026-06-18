# NVSWITCH telemetry nv-redfish dependency notes

Generated during the GB200 NVSWITCH telemetry branch setup.

## Current infra-controller dependency state

- `Cargo.toml` pins `nv-redfish = { version = "0.10.0" }`.
- `Cargo.lock` resolves `nv-redfish`, `nv-redfish-bmc-http`, `nv-redfish-core`, `nv-redfish-schema`, and `nv-redfish-csdl-compiler` to `0.10.0` from crates.io.
- `crates/health/Cargo.toml` enables standard health features but not `telemetry-service`.
- The GB200 branch has a local `nv-redfish` worktree available for companion development only:
  - `/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps`
  - Branch: `nvswitch_telemetry_gaps`
  - Base: `origin/main` at `dbd2789c987fd320d263d87524fc25fde305bc7f`

## Refreshed upstream state

- Local `/Users/mkoci/Projects/nv-redfish` was fetched from `origin` on 2026-06-18.
- Latest observed public tags: `v0.10.2`, `v0.10.1`, `v0.10.0`.
- `v0.10.2` does not appear to contain Fabric/Switch/Port/NVSwitch changes relevant to this work.
- `origin/main` includes a `telemetry-service` feature in `redfish/features.toml`.
- `origin/main` exposes `ServiceRoot::telemetry_service()` behind the `telemetry-service` feature.
- Neither `origin/main` nor `v0.10.2` has a `fabrics` feature or generated/wrapper hits for Fabric, Switch, Port, SwitchMetrics, or PortMetrics in the inspected source.

## Dependency conclusion

TelemetryService MetricReports can be wired in infra-controller by enabling `telemetry-service` and consuming the typed `TelemetryService` APIs already available in nv-redfish 0.10.x.

Redfish Fabric/Switch/Port support needs companion `nv-redfish` work if GB200 live hardware or the catalog requires those paths. The companion work should add standard DMTF schema XMLs and feature entries for Fabric, Switch, Port, SwitchMetrics, PortMetrics, Endpoint, and Zone families, plus ergonomic ServiceRoot/Fabric/Switch navigation wrappers and mock tests.

## Local development strategy

During local development, keep user-local absolute paths out of committed manifests. Use Cargo local patching via command-line `--config` for experiments against the companion `nv-redfish` worktree, for example:

```bash
cargo test -p carbide-health --lib --no-run \
  --config 'patch.crates-io.nv-redfish.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/redfish"'
```

If companion changes touch internal nv-redfish crates, patch the affected packages too:

```bash
cargo test -p carbide-health --lib --no-run \
  --config 'patch.crates-io.nv-redfish.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/redfish"' \
  --config 'patch.crates-io.nv-redfish-core.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/core"' \
  --config 'patch.crates-io.nv-redfish-schema.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/schema"' \
  --config 'patch.crates-io.nv-redfish-csdl-compiler.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/csdl-compiler"' \
  --config 'patch.crates-io.nv-redfish-bmc-http.path="/Users/mkoci/.config/superpowers/worktrees/nv-redfish/nvswitch_telemetry_gaps/bmc-http"'
```

## Final MR strategy

Do not commit local absolute path dependencies. Before final review, use one of these acceptable states:

1. A released `nv-redfish` version containing companion support, with `Cargo.toml` and `Cargo.lock` updated accordingly.
2. A reviewer-approved git revision dependency if release timing blocks final integration.
3. A documented split where infra-controller names the required `nv-redfish` companion MR and keeps local path overrides out of the final diff.
