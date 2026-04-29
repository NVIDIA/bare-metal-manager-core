# Adding Support for New Hardware

This guide explains how to add or extend hardware support in the NICo stack when new BMC/server hardware arrives that does not work out of the box. The general process is: ingest the hardware, observe where it fails, and patch the appropriate layer based on which of the three scenarios applies.

**Important:** Changes for new hardware must not break support for existing hardware. Guard new behavior behind vendor/model/firmware checks rather than modifying shared code paths.

For background on how NICo uses Redfish end-to-end, see [Redfish Workflow](../architecture/redfish_workflow.md). For the list of currently supported hardware, see the [Hardware Compatibility List](../hcl.md).

## Overview

NICo discovers and manages bare-metal hosts through their BMC (Baseboard Management Controller) via the DMTF Redfish standard. Two Rust Redfish client libraries handle this:

| Library | Role | Where Used |
|---|---|---|
| **[nv-redfish](https://github.com/NVIDIA/nv-redfish)** | Schema-driven, fast: site exploration reports, firmware inventory, sensor collection, health monitoring. **Preferred for exploration.** | Site Explorer exploration (`crates/site-explorer/`), Hardware Health (`crates/health/src/`) |
| **[libredfish](https://github.com/NVIDIA/libredfish)** | Stateful BMC interactions: boot config, BIOS setup, power control, account/credential management, lockdown | Site Explorer state controller operations (`crates/site-explorer/`) |

Site Explorer supports both libraries for generating `EndpointExplorationReport`s, controlled by the `explore_mode` configuration setting (`SiteExplorerExploreMode`):

| Mode | Behavior |
|---|---|
| `nv-redfish` | Use nv-redfish for exploration (preferred - significantly faster) |
| `libredfish` | Use libredfish for exploration (legacy) |
| `compare-result` | Run both and compare results (transition/validation) |

When new hardware arrives, failures can surface in **either** library. Exploration failures show up in whichever `explore_mode` is active (increasingly nv-redfish). State controller failures (boot order, BIOS setup, lockdown, credential rotation) show up in libredfish, which remains the library used for all write operations against BMCs. Both libraries may need changes to support a new platform.

Beyond the Redfish libraries, **NICo itself** has vendor-aware logic that also needs updating - see [Changes in NICo](#changes-in-nico).

## The Three Scenarios

### Scenario 1: Completely New BMC Vendor

The hardware uses a BMC firmware stack that does not map to any existing `RedfishVendor` variant.

**What to do:**

1. **Add a `RedfishVendor` variant** in `libredfish/src/model/service_root.rs`.

2. **Extend vendor detection** in `ServiceRoot::vendor()` (same file). The vendor string comes from `GET /redfish/v1` - the `Vendor` field, or failing that, the first key in the `Oem` object. If the vendor string alone is not enough to distinguish the BMC (e.g., the vendor is "Lenovo" but some models use an AMI-based BMC), use secondary signals like `self.has_ami_bmc()` or `self.product`.

3. **Create a vendor module** (or reuse an existing one). Each vendor has a file `libredfish/src/<vendor>.rs` containing a `Bmc` struct that implements the `Redfish` trait. If the new vendor's BMC is very close to an existing one (e.g., LenovoAMI reuses `ami::Bmc`), you can route to the existing implementation.

4. **Wire up `set_vendor`** in `libredfish/src/standard.rs` to dispatch the new variant to the appropriate `Bmc` implementation.

5. **Implement the `Redfish` trait** for the new `Bmc`. Start by delegating to `RedfishStandard` and override methods as needed. The methods below are grouped by how they are used in the state machine; almost all need vendor-specific overrides.

   **BIOS / machine setup** - called during initial ingestion and instance creation to configure UEFI settings:
   - `machine_setup()` - applies BIOS attributes (names differ per vendor and model)
   - `machine_setup_status()` - polls whether all `machine_setup` changes have taken effect
   - `is_bios_setup()` - lightweight check used during instance creation (`PollingBiosSetup`) to confirm BIOS is ready before proceeding to boot order configuration

   **Lockdown** - called to secure the BMC before tenant use and unlocked during instance termination or reconfiguration:
   - `lockdown()` - enable/disable BMC security lockdown
   - `lockdown_status()` - polled by the state controller to confirm lockdown state; wrong results cause machines to get stuck
   - `lockdown_bmc()` - lower-level BMC-specific lockdown (e.g., iDRAC lockdown on Dell, distinct from BIOS lockdown)

   **Boot order** - called during ingestion to set DPU-first boot and during DPU reprovisioning:
   - `set_boot_order_dpu_first()` - reorder boot options so the DPU boots first (platform-specific boot option discovery)
   - `boot_once()` - one-time boot from a specific target (e.g., `UefiHttp` for DPU HTTP boot path)
   - `boot_first()` - persistently change boot order to a given target

   **Serial console** - SSH console access setup:
   - `setup_serial_console()` - configure BMC serial-over-LAN
   - `serial_console_status()` - polled to confirm setup; incorrect results stall provisioning

   **Credential management** - called during initial ingestion to rotate factory defaults:
   - `change_password()` - rotate BMC user password
   - `change_uefi_password()` / `clear_uefi_password()` - UEFI password management (only tested on Dell, Lenovo, NVIDIA)
   - `set_machine_password_policy()` - apply password-never-expires policy (vendor-specific)

   **Important:** Pay careful attention to all **status/polling methods** (`is_bios_setup()`, `lockdown_status()`, `machine_setup_status()`, `serial_console_status()`, etc.). The state controller polls these during provisioning, instance creation, instance termination, and reprovisioning to decide when to advance state. If they return incorrect results, machines will get stuck in polling states, fail to terminate properly, or skip required configuration steps.

6. **Add OEM model types** if needed in `libredfish/src/model/oem/<vendor>.rs`.

7. **Add unit tests** for vendor detection and create a **mockup directory** for integration tests (see [Testing](#testing)).

8. **Update nv-redfish** - since nv-redfish is the preferred library for site exploration, it will likely need changes too. See [nv-redfish Quirks](#adding-nv-redfish-quirks-for-exploration-and-health-monitoring).

9. **Update NICo** - add the vendor to `BMCVendor`, `HwType`, and handle any state controller quirks. See [Changes in NICo](#changes-in-nico).

### Scenario 2: New Server Model with Quirks

The hardware uses an already-supported BMC vendor but the specific model has quirks: different BIOS attribute names, unusual boot option paths, model-specific OEM extensions, etc.

**What to do:**

1. **Identify the model string.** `GET /redfish/v1/Systems/{id}` returns a `Model` field. The function `model_coerce()` in `libredfish/src/lib.rs` normalizes this by replacing spaces with underscores.

2. **Use BIOS / OEM manager profiles** for config-driven differences. NICo supports per-vendor, per-model BIOS settings via the `BiosProfileVendor` type in `lib.rs`, letting you define model-specific attributes in config (TOML) without code changes.

3. **Add model-specific branches** in the vendor module when profiles are not enough. Use the model/product string from `ComputerSystem` to gate behavior.

4. **Handle missing or renamed attributes.** Check the actual BIOS attributes via `GET /redfish/v1/Systems/{id}/Bios` on the target hardware. If an attribute is missing, add a guard that logs and skips rather than failing.

### Scenario 3: New Firmware for an Existing Model

A firmware update for an already-supported model introduces regressions: removed endpoints, changed response schemas, renamed attributes, etc.

**What to do:**

1. **Compare old and new firmware Redfish responses.** Use `curl` or `carbide-admin-cli redfish browse` to `GET` endpoints on both versions and diff.

2. **Add defensive handling** where endpoints may no longer exist - catch `404` errors and fall through.

3. **Fix deserialization issues**: null values in arrays (custom deserializers), new enum values, missing required fields (`Option<T>`).

4. **Adjust OEM-specific paths** if the firmware reorganizes its Redfish tree.

5. **Guard behavioral changes behind firmware version checks** if needed, using `ServiceRoot.redfish_version` or firmware inventory versions.

## Changes in NICo

Beyond the Redfish libraries, NICo itself has vendor-aware logic that needs updating for new hardware.

### `BMCVendor` enum (`crates/bmc-vendor/src/lib.rs`)

NICo has its own `BMCVendor` enum, distinct from libredfish's `RedfishVendor`. It is used throughout NICo for vendor-specific branching in the state controller, credential management, and exploration. When adding a new vendor:

1. **Add the variant** to `BMCVendor`.
2. **Add the `From<RedfishVendor>` mapping** so libredfish's vendor detection flows into NICo's enum.
3. **Add parsing** in `From<&str>`, `from_udev_dmi()`, and `from_tls_issuer()` as applicable.

### `HwType` enum (`crates/bmc-explorer/src/hw/mod.rs`)

The `bmc-explorer` crate (used by the nv-redfish exploration path) classifies hardware into `HwType` variants. Each variant maps to a `BMCVendor` via `bmc_vendor()`. For a new hardware type, add a variant to `HwType` and implement the required methods. If the hardware type has unique exploration behavior, add a corresponding module under `crates/bmc-explorer/src/hw/`.

### State controller vendor branches

The state controller (`crates/api/src/state_controller/machine/handler.rs`) has vendor-specific logic gated on `BMCVendor` for operations that cannot be handled generically in libredfish. Examples:

- **Factory credential rotation**: On first exploration, NICo changes the factory default BMC password. This is vendor-aware - ensure the new vendor's credential rotation path works correctly.
- **UEFI password setting**: Only tested on Dell, Lenovo, and NVIDIA - other vendors log a warning and skip.
- **Power cycling**: Lenovo SR650 V4s use IPMI chassis reset instead of Redfish `ForceRestart` to avoid killing DPU power. Lenovo BMCs need an explicit `bmc_reset()` after firmware upgrades.
- **Lockdown**: Dell requires BMC lockdown to be disabled separately before UEFI password changes.

Review `handler.rs` for `bmc_vendor().is_*()` calls and add branches for the new vendor where its behavior differs.

## Testing with `carbide-admin-cli redfish`

The fastest way to validate libredfish changes against a real BMC is to compile `carbide-admin-cli` with a **local checkout of libredfish** and use the `redfish` subcommand to test specific operations directly, rather than waiting for Site Explorer or the state machine to exercise the code path.

### Setup: Use a local libredfish checkout

Place your libredfish checkout inside the NICo workspace (or anywhere accessible), then override the dependency in the workspace `Cargo.toml`:

```toml
# Cargo.toml (workspace root)
[workspace.dependencies]
# Comment out the git version:
# libredfish = { git = "https://github.com/NVIDIA/libredfish.git", tag = "v0.43.5" }
# Point to your local checkout instead:
libredfish = { path = "libredfish" }
```

Then build the CLI from the `crates/admin-cli` directory:

```bash
cd crates/admin-cli
cargo build
```

### Running commands against a real BMC

The `redfish` subcommand talks directly to a BMC - no NICo deployment needed:

```bash
# Check if vendor detection and basic connectivity work
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> get-power-state

# Read BIOS attributes to see what the BMC exposes
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> bios-attrs

# Test machine setup (the core provisioning step)
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> machine-setup

# Check if machine setup succeeded
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> machine-setup-status

# Test boot order (set DPU first)
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> set-boot-order-dpu-first --boot-interface-mac <dpu-mac>

# Test lockdown
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> lockdown-enable
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> lockdown-status

# Browse any Redfish endpoint directly
./target/debug/carbide-admin-cli redfish --address <bmc-ip> --username <user> --password <pass> browse --uri /redfish/v1
```

If all of these commands work correctly, there is a good chance the hardware will work end-to-end through Site Explorer and the state machine.

## Code Structure Reference

```
libredfish/
├── src/
│   ├── lib.rs                    # Redfish trait, BiosProfile types, model_coerce()
│   ├── standard.rs               # RedfishStandard: defaults + set_vendor() dispatch
│   ├── network.rs                # create_client(): ServiceRoot → vendor → set_vendor
│   ├── ami.rs, dell.rs, hpe.rs,  # Vendor-specific Redfish trait implementations
│   │   lenovo.rs, supermicro.rs, ...
│   └── model/
│       ├── service_root.rs       # RedfishVendor enum, vendor detection
│       ├── oem/                  # Vendor-specific OEM data models
│       └── testdata/             # JSON fixtures for unit tests
├── tests/
│   ├── integration_test.rs       # Per-vendor integration tests
│   ├── mockups/<vendor>/         # Redfish JSON mockup trees
│   └── redfishMockupServer.py    # Python server for mockups

nico/
├── crates/bmc-vendor/src/lib.rs        # BMCVendor enum + From<RedfishVendor>
├── crates/bmc-explorer/src/hw/mod.rs   # HwType enum (nv-redfish exploration)
├── crates/api/src/state_controller/    # Vendor-specific state machine logic
└── crates/admin-cli/src/redfish/       # carbide-admin-cli redfish subcommand
```

## Adding nv-redfish Quirks for Exploration and Health Monitoring

nv-redfish is the preferred library for site exploration reports and is also used for health monitoring (`carbide-hw-health`). If the new hardware causes failures in either path, the fix goes into nv-redfish.

1. **Add a `Platform` variant** in `nv-redfish/redfish/src/bmc_quirks.rs` if the quirk is platform-specific.

2. **Map the variant** in `BmcQuirks::new()` using the vendor string, redfish version, and product from the service root.

3. **Add quirk methods** for each workaround. Common quirks:
   - `bug_missing_root_nav_properties()` - BMC omits `Systems`/`Chassis`/`Managers` from service root
   - `expand_is_not_working_properly()` - `$expand` query parameter broken
   - `wrong_resource_status_state()` - non-standard `Status.State` enum values
   - `fw_inventory_wrong_release_date()` - invalid date formats

4. **Add OEM feature support** if needed. OEM extensions are gated behind Cargo features (`oem-ami`, `oem-dell`, `oem-hpe`, etc.) in `nv-redfish/redfish/Cargo.toml`.

## Testing

### Unit Tests

Add vendor detection tests in `libredfish/src/model/service_root.rs`. For complex detection (like `LenovoAMI` which checks the `Oem` field), use JSON test fixtures in `src/model/testdata/`.

### Testing Against Real Hardware

Use `carbide-admin-cli redfish` with a local libredfish checkout (see [above](#testing-with-carbide-admin-cli-redfish)) to validate all key operations before deploying. Then test the full cycle through a NICo instance: discovery → ingestion → BIOS setup → boot order → lockdown → health monitoring.

