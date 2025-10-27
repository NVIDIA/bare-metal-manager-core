# mlxconfig_embedded

Example command-line interface and utilities for working with the Mellanox hardware configuration registry.

## Overview

The `mlxconfig_embedded` crate provides a sample CLI tool for working with MLX hardware configurations provided by `mlxconfig_registry` and `mlxconfig_variables`. It offers example subcommands for registry management, device compatibility checking, and configuration generation from MLX `show_confs` output.

In practice, this will be embedded into `forge_dpu_agent` (for DPU management), `scout` (for DPA management), and probably `carbide-api` (for server-side validation of configuration).

## Features

- **Registry Management**: List, show, and validate hardware configuration registries
- **Device Compatibility**: Check if specific hardware is compatible with registries
- **Configuration Generation**: Parse MLX `show_confs` output into YAML registries
- **Multiple Output Formats**: Table, JSON, and YAML output support
- **Constraint Validation**: Verify device compatibility with registry constraints

## Installation

Build from source:
```bash
cargo build --release
```

The binary will be available at `target/release/mlxconfig_embedded`.

## Command Overview

```bash
mlxconfig_embedded --help
```

### Available Commands

- `version` - Show version information
- `registry list` - List all available registries
- `registry show <name>` - Show detailed registry information
- `registry validate <file>` - Validate a YAML registry file
- `registry generate <input>` - Generate YAML from show_confs output
- `registry check <name>` - Check device compatibility with registry

## Usage Examples

### List All Registries

```bash
$ mlxconfig_embedded registry list
+------------------+-----------+-------------+
| Name             | Variables | Constraints |
+------------------+-----------+-------------+
| foo_registry     | 6         | none        |
| bar_registry     | 4         | none        |
+------------------+-----------+-------------+
```

### Show Registry Details

```bash
$ mlxconfig_embedded registry show foo_registry
+---------------+----------------+
| Registry Name | foo_registry   |
+---------------+----------------+
| Variables     | 4              |
+---------------+----------------+
| Constraints   | none           |
+---------------+----------------+
| Variable Name | Read-Write | Type             | Description             |
+---------------+------------+------------------+-------------------------+
| cpu_frequency | RW         | integer          | CPU frequency in MHz    |
| enable_turbo  | RW         | boolean          | Enable CPU turbo mode   |
| device_name   | RO         | string           | Hardware device name    |
| power_mode    | RW         | enum [low, me... | Power management mode   |
+---------------+------------+------------------+-------------------------+
```

### Show Registry as JSON

```bash
$ mlxconfig_embedded registry show foo_registry --output json
{
  "name": "foo_registry",
  "variables": [
    {
      "name": "cpu_frequency",
      "description": "CPU frequency in MHz",
      "read_only": false,
      "spec": "Integer"
    },
    // ... more variables
  ],
  "constraints": {}
}
```

### Validate Registry YAML

```bash
$ mlxconfig_embedded registry validate databases/registry-foo.yaml
YAML file is valid!
Registry: 'foo_registry'
Variables: 4
No constraints (compatible with all hardware)
```

### Generate Registry from show_confs

```bash
# Parse MLX show_confs output into YAML registry
$ mlxconfig_embedded registry generate show_confs_output.txt --out-file new-registry.yaml
Generated registry YAML: new-registry.yaml

# Or output to stdout
$ mlxconfig_embedded registry generate show_confs_output.txt
name: "MLX Hardware Configuration Registry"
variables:
  - name: "CPU_FREQUENCY"
    description: "CPU frequency setting in MHz"
    read_only: false
    spec:
      type: "Integer"
  # ... more variables
```

### Check Device Compatibility

```bash
$ mlxconfig_embedded registry check bluefield3_registry \
    --device-type "Bluefield3" \
    --part-number "900-9D3D4-00EN-HA0" \
    --fw-version "32.41.130"

🔍 Compatibility Check
======================
Registry: 'bluefield3_registry'

Device Information:
  Device type: Bluefield3
  Part number: 900-9D3D4-00EN-HA0
  FW version: 32.41.130

Registry Constraints: Device types: [Bluefield3]; Part numbers: [900-9D3D4-00EN-HA0]; FW versions: [32.41.130]

COMPATIBLE
```

### Default Information Display

Running without commands shows system overview:

```bash
$ mlxconfig_embedded
Mellanox Hardware Configuration Registry
=====================================
Summary:
   • Total registries: 2
   • Total variables: 10
   • Constrained registries: 0
   • Universal registries: 2

Use --help to see available commands
Use 'registry list' to see all available registries
Use 'registry show <name>' to see registry details
```

## show_confs Parser

The CLI includes a parser for MLX `show_confs` output that automatically converts hardware configuration listings into YAML registry format.

### Supported show_confs Patterns

The parser recognizes these MLX configuration patterns:

- **Variable definitions**: `VARIABLE_NAME=<type> description`
- **Boolean options**: `OPTION=<False|True> description`
- **Numeric values**: `SETTING=<NUM> description`
- **Enum choices**: `MODE=<option1|option2|option3> description`
- **Binary data**: `DATA=<BINARY> description`
- **Byte arrays**: `BUFFER=<BYTES> description`

### Example show_confs Input
```
List of configurations:
ADVANCED CONFIG:
    CPU_FREQUENCY=<NUM> CPU frequency setting in MHz
    TURBO_MODE=<False|True> Enable or disable turbo mode
    POWER_LEVEL=<low|medium|high|turbo> Power management setting
    DEVICE_NAME=<STRING> Hardware device identifier
```

### Generated YAML Output
```yaml
name: "MLX Hardware Configuration Registry"
variables:
  - name: "CPU_FREQUENCY"
    description: "CPU frequency setting in MHz"
    read_only: false
    spec:
      type: "Integer"
  - name: "TURBO_MODE"
    description: "Enable or disable turbo mode"
    read_only: false
    spec:
      type: "Enum"
      config:
        options: ["False", "True"]
  - name: "POWER_LEVEL"
    description: "Power management setting"
    read_only: false
    spec:
      type: "Enum"
      config:
        options: ["low", "medium", "high", "turbo"]
  - name: "DEVICE_NAME"
    description: "Hardware device identifier"
    read_only: false
    spec:
      type: "String"
```

## Configuration Architecture

This CLI tool accesses compile-time embedded registries from `mlxconfig_registry`. The data flow is:

```
YAML Files → build.rs → Static Registries → CLI Access
databases/  → Generation → mlxconfig_registry → mlxconfig_embedded
```

All registry data is validated at compile time and embedded as static constants, providing:
- **Zero runtime parsing overhead**
- **Impossible to ship invalid configurations**
- **Fast application startup**
- **Memory efficient operation**

## Output Formats

### Table Format (Default)
Human-readable tables with automatic text wrapping and formatting.

### JSON Format
Machine-readable JSON for integration with other tools:
```bash
mlxconfig_embedded registry show registry_name --output json
```

### YAML Format
YAML output for configuration file generation:
```bash
mlxconfig_embedded registry show registry_name --output yaml
```
