# Component Manager Configuration

This document explains the configuration files for the Component Manager system.

## Overview

The Component Manager configuration controls:
1. Which implementation to use for each component type (compute, NVL switch, power shelf)
2. Manager behavior settings for selected implementations
3. Which API providers to enable and their client settings

Timing parameters for power control and firmware update operations are generally
configured **per-rule** via action parameters in operation rules. Manager-wide
behavior settings, such as compute power-call staggering, live under
`manager_configs`.

## Configuration Files

| File | Purpose |
|------|---------|
| `componentmanager.test.yaml` | Testing/development configuration using mock implementations |
| *(embedded)* | Service default embedded in the binary via `builtin.LoadConfig("")` |

The production config is compiled into the binary. No YAML file is needed for production
deployments. A YAML file is only required when overriding defaults (e.g., for testing).
When a YAML file path is supplied, the file is authoritative and is not merged
with the embedded defaults.

## Configuration Structure

### Component Managers

```yaml
component_managers:
  compute: <implementation>
  nvswitch: <implementation>
  powershelf: <implementation>
```

Maps each component type to its implementation. Service-loaded YAML files must
include at least one `component_managers` entry. Partial maps are supported:
missing component types are not filled from embedded defaults and remain
unconfigured until explicitly added.

Available implementations:

| Component Type | Available Implementations | Description |
|----------------|---------------------------|-------------|
| `compute` | `nico`, `mock` | Manages compute nodes |
| `nvswitch` | `nico`, `nvswitchmanager`, `mock` | Manages NVLink switches |
| `powershelf` | `nico`, `psm`, `mock` | Manages power shelves |

### Providers

```yaml
providers:
  nico:
    timeout: "<duration>"
  nvswitchmanager:
    timeout: "<duration>"
  psm:
    timeout: "<duration>"
```

Configures API client providers. Provider configs are completed from
`component_managers` using provider defaults. If `providers` is present, entries
in that section override defaults for those providers; any required provider not
listed there is still added with its default config. `providers: {}` is
equivalent to omitting the section for provider-backed component managers.

| Provider | Used By | Description |
|----------|---------|-------------|
| `nico` | compute, nvswitch, powershelf/nico | NICo API for machine management |
| `nvswitchmanager` | nvswitch/nvswitchmanager | NV-Switch Manager API for NVLink switch management |
| `psm` | powershelf/psm | Power Shelf Manager API |

### Manager Configs

```yaml
manager_configs:
  compute:
    nico:
      compute_power_delay: "<duration>"
```

Configures behavior for a selected component manager implementation. The keys
are the descriptor identity: component type, then implementation name. Entries
must match the selected `component_managers` implementation.

| Manager | Option | Type | Default | Description |
|---------|--------|------|---------|-------------|
| `compute/nico` | `compute_power_delay` | duration string | `2s` | Delay between sequential power control calls for compute trays. Prevents overwhelming the power delivery system. Set to `0s` to disable. |

#### Provider Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `timeout` | duration string | `1m` (nico, nvswitchmanager), `30s` (psm) | gRPC call timeout |

Duration strings use Go format: `30s`, `1m`, `2m30s`, etc.

## Examples

### Production Configuration (embedded default)

```yaml
# Equivalent to builtin.LoadConfig("")
component_managers:
  compute: nico
  nvswitch: nico
  powershelf: nico

manager_configs:
  compute:
    nico:
      compute_power_delay: "2s"

providers:
  nico:
    timeout: "1m"
```

### Test Configuration

```yaml
# Uses mock implementations - no external dependencies
component_managers:
  compute: mock
  nvswitch: mock
  powershelf: mock

# No providers section needed for mock implementations
```

### Mixed Configuration (e.g., partial testing)

```yaml
# Real power shelf management, mock compute/nvswitch
component_managers:
  compute: mock
  nvswitch: mock
  powershelf: psm

providers:
  psm:
    timeout: "30s"
```

## Provider Completion

Providers are automatically enabled based on the component manager implementations:

- If any component uses `nico` → NICo provider is enabled with defaults
- If `nvswitch` uses `nvswitchmanager` → NV-Switch Manager provider is enabled with defaults
- If `powershelf` uses `psm` → PSM provider is enabled with defaults

This allows minimal configuration:

```yaml
component_managers:
  compute: nico
  nvswitch: nvswitchmanager
  powershelf: psm
# Providers auto-enabled based on implementations above
```

Provider entries can override only the providers that need non-default settings:

```yaml
component_managers:
  compute: nico
  nvswitch: nvswitchmanager
  powershelf: psm

providers:
  nvswitchmanager:
    timeout: "1m30s"
  psm:
    timeout: "45s"
# nico is still added with defaults
```

## Usage

Set the configuration file path via:

1. **Command line flag**: `--component-config <path>`
2. **Environment variable**: `COMPONENT_MANAGER_CONFIG=<path>`
3. **Default**: embedded service config

## Timing Parameters

Power control and firmware update timing (delays, poll intervals, timeouts) are
configured **per-rule** via action parameters in operation rules, not here.

See `CLAUDE.md` (Action-Based Operation Rules section) and
`examples/operation-rules-example.yaml` for examples.
