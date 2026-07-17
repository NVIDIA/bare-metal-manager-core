# Component Manager RMS Backends (Day 1)

Operator guide for configuring **Rack Manager Service (RMS)** backends in the
`[component_manager]` section of `nico-api` site config, and the **rack profile**
data those backends require for node type resolution.

`[component_manager]` manages compute trays, NVLink switches, and power shelves.
When a role's backend is set to `rms`, NICo resolves the RMS node type from the
rack profile. If a configured
rack profile definition is missing required fields or is ambiguous, `nico-api`
**fails configuration validation at startup**. Per-rack `rack_profile_id`
assignments are not checked at startup. Those errors surface at runtime when an
RMS operation runs (refer to [Startup validation](#startup-validation)).

Canonical field reference: [`crates/api-core/src/cfg/README.md`](https://github.com/NVIDIA/infra-controller/tree/main/crates/api-core/src/cfg/README.md).
Configure the `[rms]` block (mTLS connectivity to the external RMS) separately;
the examples on this page cover the component-manager and rack-profile fields.

---

## What the rack profile provides

For RMS component-manager backends, the rack profile supplies two facts:

- **Product family**: `product_family`. Required for RMS-backed operations;
  currently accepts `gb200` or `gb300`.
- **Vendor**: `rack_capabilities.<role>.vendor`, for each role using an RMS
  backend.

## Startup validation

NICo validates configured rack profiles at startup **when any component-manager
backend is set to `rms`**. The backend fields default to `rms`, so a deployment
that enables a single RMS role must **explicitly set the other backend fields to
non-RMS values**. Startup validation checks the product family and the vendor
fields for enabled RMS roles.

For example, if `power_shelf_backend = "rms"` and the other backend fields are
set to non-RMS values, then `rack_capabilities.power_shelf.vendor` is the sole
required vendor field.

`[rack_profiles]` must contain at least one profile when any component-manager
backend is set to `rms`; an empty table is rejected at startup.

Each rack that uses an RMS-backed operation must have a `rack_profile_id` matching
a key under `[rack_profiles]`. Startup validation does not scan existing rack
database rows, so missing or unknown per-rack profile IDs are still checked when
an RMS operation runs.

## Canonical vendor names

Use these vendor names in config:

| Role | Canonical values |
| --- | --- |
| Compute, when `compute_tray_backend = "rms"` | `NVIDIA`; `Lenovo` (GB300; not valid for GB200) |
| Switch, when `nv_switch_backend = "rms"` | `NVIDIA` |
| Power shelf, when `power_shelf_backend = "rms"` | `LiteOn`, `Delta` |

`product_family` is **not normalized**. It must exactly match one of the accepted
lowercase values (`gb200`, `gb300`); values like `GB200` are rejected.

Vendor matching is more forgiving: values are trimmed, case-insensitive, and ignore
spaces, hyphens, and underscores, so `NVIDIA`, `nvidia`, `LiteOn`, `liteon`,
`Lite-On`, and `lite_on` all work. Common company-suffix text also works when the
normalized value starts with the canonical vendor, but the canonical values above
are preferred for operator-supplied config.

---

## Examples

### GB200 rack, all component-manager roles use RMS

```toml
[component_manager]
compute_tray_backend = "rms"
nv_switch_backend = "rms"
power_shelf_backend = "rms"

[rack_profiles.NVL72]
product_family = "gb200"
rack_hardware_topology = "gb200_nvl72r1_c2g4_topology"

[rack_profiles.NVL72.rack_capabilities.compute]
vendor = "NVIDIA"

[rack_profiles.NVL72.rack_capabilities.switch]
vendor = "NVIDIA"

[rack_profiles.NVL72.rack_capabilities.power_shelf]
vendor = "LiteOn"
```

### GB300 rack, Lenovo compute trays and Delta power shelves

```toml
[component_manager]
compute_tray_backend = "rms"
nv_switch_backend = "rms"
power_shelf_backend = "rms"

[rack_profiles.NVL72_GB300]
product_family = "gb300"
rack_hardware_topology = "gb300_nvl72r1_c2g4_topology"

[rack_profiles.NVL72_GB300.rack_capabilities.compute]
vendor = "Lenovo"

[rack_profiles.NVL72_GB300.rack_capabilities.switch]
vendor = "nvidia"

[rack_profiles.NVL72_GB300.rack_capabilities.power_shelf]
vendor = "delta"
```

### Power shelf backend uses RMS; compute and switch do not

The compute and switch component-manager backends are explicitly set to non-RMS
values, so component-manager startup validation requires the power shelf vendor
field and no others:

```toml
[component_manager]
compute_tray_backend = "core"
nv_switch_backend = "nsm"
power_shelf_backend = "rms"

[component_manager.nsm]
url = "http://nsm.example.internal:50052"

[rack_profiles.NVL72_POWER]
product_family = "gb200"
rack_hardware_topology = "gb200_nvl72r1_c2g4_topology"

[rack_profiles.NVL72_POWER.rack_capabilities.power_shelf]
vendor = "Lite-On"
```

---

## Accepted values

| Field | Accepted values |
| ----- | --------------- |
| `product_family`, when an RMS-backed operation uses the profile | Exact match: `gb200`, `gb300` |
| `rack_hardware_topology` | `gb200_nvl36r1_c2g4_topology`, `gb200_nvl72r1_c2g4_topology`, `gb300_nvl36r1_c2g4_topology`, `gb300_nvl72r1_c2g4_topology` |
| Compute profile vendor, when `compute_tray_backend = "rms"` | `nvidia`, `lenovo` after normalization (`lenovo` requires `product_family = "gb300"`; GB200 compute accepts `nvidia`) |
| Switch profile vendor, when `nv_switch_backend = "rms"` | `nvidia` after normalization |
| Power shelf profile vendor, when `power_shelf_backend = "rms"` | `liteon`, `delta` after normalization |

## Machine ingestion note

The separate site-explorer machine-ingestion path performs an RMS slot/tray lookup
and uses the rack profile for node type resolution. This path runs when **both**
conditions hold:

1. An RMS client is configured (the `[rms]` block is present).
2. The machine has a `rack_id`.

Under those conditions the profile must include compute `product_family` and
`vendor` data. Setting `compute_tray_backend` to a non-RMS value does not
remove this requirement.
