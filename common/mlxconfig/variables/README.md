# mlxconfig_variables

Core type definitions and validation logic for Mellanox hardware configuration.

## Overview

The `mlxconfig_variables` crate provides the foundational types and validation logic used throughout the MLX configuration ecosystem. This crate defines the data structures for hardware configuration variables, device constraints, and registries, along with builder patterns for easy construction.

## Key Components

### Configuration Variables (`MlxConfigVariable`)

Represents a single hardware configuration parameter with:
- **Name**: Unique identifier for the variable
- **Description**: Human-readable description
- **Read-only flag**: Whether the variable can be modified
- **Spec**: Type specification defining the variable's data type and constraints

### Variable Specifications (`MlxVariableSpec`)

Strongly-typed enum defining all supported variable types:

- **Simple types**: `Boolean`, `Integer`, `String`, `Binary`, `Bytes`, `Array`, `Opaque`
- **Enum types**: `Enum { options }` - choice from predefined values
- **Preset types**: `Preset { max_preset }` - numbered presets (0 to max)
- **Array types**: `BooleanArray`, `IntegerArray`, `BinaryArray` - fixed-size arrays
- **Complex arrays**: `EnumArray` - arrays of enum values

### Hardware Registries (`MlxVariableRegistry`)

Collections of related configuration variables with optional device constraints:
- **Name**: Registry identifier
- **Variables**: List of configuration variables
- **Constraints**: Optional device compatibility rules

### Device Constraints (`RegistryTargetConstraints`)

Define which hardware devices can use specific registries:
- **Device types**: e.g., "Bluefield3", "ConnectX-7"
- **Part numbers**: e.g., "900-9D3D4-00EN-HA0"
- **Firmware versions**: e.g., "32.41.130"

### Device Information (`DeviceInfo`)

Container for actual device details used in constraint validation.

## Builder Patterns

All types include builder patterns for clean construction:

```rust
use mlxconfig_variables::*;

// Build a simple boolean variable
let variable = MlxConfigVariable::builder()
    .name("turbo_enabled")
    .description("Enable turbo boost mode")
    .read_only(false)
    .spec(
        MlxVariableSpec::builder()
            .boolean()
            .build()
    )
    .build();

// Build an enum variable
let power_mode = MlxConfigVariable::builder()
    .name("power_mode")
    .description("Power management setting")
    .read_only(false)
    .spec(
        MlxVariableSpec::builder()
            .enum_type()
            .with_options(vec!["low", "medium", "high"])
            .build()
    )
    .build();

// Build a registry with constraints
let registry = MlxVariableRegistry::builder()
    .name("Bluefield3 Registry")
    .variables(vec![variable, power_mode])
    .with_device_types(vec!["Bluefield3"])
    .with_part_numbers(vec!["900-9D3D4-00EN-HA0"])
    .build();
```

## Constraint Validation

The crate provides runtime validation of device compatibility:

```rust
use mlxconfig_variables::*;

let device = DeviceInfo::new()
    .with_device_type("Bluefield3")
    .with_part_number("900-9D3D4-00EN-HA0")
    .with_fw_version("32.41.130");

let result = registry.validate_compatibility(&device);

match result {
    ConstraintValidationResult::Valid => {
        println!("Device is compatible!");
    },
    ConstraintValidationResult::Invalid { reasons } => {
        println!("Incompatible: {:?}", reasons);
    },
    ConstraintValidationResult::Unconstrained => {
        println!("No constraints - universally compatible");
    }
}
```

## YAML Serialization

All types support serde serialization for YAML configuration files:

```yaml
name: "example_registry"
constraints:
  device_types:
    - "Bluefield3"
  part_numbers:
    - "900-9D3D4-00EN-HA0"
variables:
  - name: "cpu_frequency"
    description: "CPU frequency in MHz"
    read_only: false
    spec:
      type: "integer"
  - name: "power_mode"
    description: "Power management mode"
    read_only: false
    spec:
      type: "enum"
      config:
        options: ["low", "medium", "high"]
```

## Dependencies

- `serde` with `derive` feature - for serialization support
- `serde_yaml` - for YAML format support

## Usage

Add to your `Cargo.toml` (assuming you're going into `common/`):

```toml
[dependencies]
mlxconfig_variables = { path = "../common/mlxconfig_variables" }
```

This crate is designed to be used by:
- **build.rs scripts** that generate static registries at compile time
- **Runtime applications** that need to validate device compatibility
- **CLI tools** that work with configuration data
- **Libraries** that extend the MLX configuration system

## Architecture Notes

This crate is the foundation layer that provides:
1. **Type safety** through Rust's type system
2. **Validation logic** for device constraints
3. **Builder patterns** for ergonomic construction
4. **Serialization support** for persistence and interchange
5. **Zero-cost abstractions** with compile-time guarantees

The types defined here are consumed by `mlxconfig_registry` for compile-time embedding and by `mlxconfig_embedded` for CLI functionality.
