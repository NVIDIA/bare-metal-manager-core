# mlxconfig_variables

Core type definitions and validation logic for Mellanox hardware configuration.

## Overview

The `mlxconfig_variables` crate provides the foundational types and validation logic used throughout our little
`mlxconfig` configuration ecosystem. This crate defines the data structures for hardware configuration variables, device
constraints, and registries, along with builder patterns for easy construction and a powerful value creation system for
working with actual configuration data.

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

### Configuration Values (`MlxConfigValue`)

Typed values that pair configuration variables with their actual data:

- **Variable**: The configuration variable definition
- **Value**: Strongly-typed value that matches the variable's spec
- **Validation**: Automatic type and constraint validation
- **Display**: Built-in formatting for user interfaces

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

## Value Creation System

The crate provides a powerful, type-safe value creation system that automatically handles conversion and validation
based on variable specifications. This system is designed to work seamlessly with `mlxconfig` JSON responses while
providing compile-time safety.

### Value Creation

The core `with()` method automatically converts input types based on the variable's specification:

```rust
use mlxconfig_variables::*;

// Get a variable from a registry
let registry = /* ... */;
let turbo_var = registry.get_variable("enable_turbo").unwrap();
let freq_var = registry.get_variable("cpu_frequency").unwrap();
let power_var = registry.get_variable("power_mode").unwrap();

// Use with to create an `MlxConfigValue` for any type.
let turbo_value = turbo_var.with(true) ?;                   // Boolean
let freq_value = freq_var.with(2400) ?;                     // Integer  
let power_value = power_var.with("high") ?;                 // Enum (with option validation)
let array_value = bool_array_var.with(vec![true, false]) ?; // Boolean array

// Display values
println!("Turbo: {}", turbo_value);     // "true"
println!("Frequency: {}", freq_value);  // "2400"
println!("Power: {}", power_value);     // "high"
```

### String Parsing for `mlxconfig` JSON Integration

The system natively handles string input from `mlxconfig` JSON responses, with automatic parsing based on
variable types:

```
// From JSON - everything comes as strings
let json_response = r#"{
  "enable_turbo": "true",
  "cpu_frequency": "2400", 
  "power_mode": "high",
  "gpio_modes": ["input", "output", "bidirectional"]
}"#;

let data: serde_json::Value = serde_json::from_str(json_response)?;
let registry = registries::get("my_registry").unwrap();

// Process JSON values
for (var_name, json_value) in data.as_object().unwrap() {
 if let Some(variable) = registry.get_variable(var_name) {
  let config_value = match json_value {
   // Single string values - automatic type conversion.
   serde_json::Value::String(s) => {
   variable.with(s.clone())?  // Boolean, Integer, Enum, etc.
  }

  // Array values - parse each string element.
  serde_json::Value::Array(arr) => {
   let strings: Vec = arr.iter()
   .filter_map( | v | v.as_str())
   .map(String::from)
   .collect();
   variable.with(strings)?  // BooleanArray, IntegerArray, etc.
  }
  _ => continue,
  };
  println ! ("Set {}: {}", config_value.name(), config_value);
 }
}
```

### Supported String Conversions

The system intelligently parses strings based on variable specifications:

#### Boolean Variables

- **True**: `"true"`, `"1"`, `"yes"`, `"on"`, `"enabled"` (case insensitive)
- **False**: `"false"`, `"0"`, `"no"`, `"off"`, `"disabled"` (case insensitive)

#### Integer Variables

- Standard integer parsing: `"42"`, `"-123"`, `"0"`

#### Enum Variables

- Validates against allowed options: `"high"` (if "high" is in the enum options)

#### Preset Variables

- Parses number and validates range: `"5"` (if 5 ≤ max_preset)

#### Binary/Bytes/Opaque Variables

- Hex parsing with or without prefix: `"0x1a2b3c"`, `"1A2B3C"`

#### Array Variables

- **BooleanArray**: `["true", "0", "yes", "disabled"]` → `[true, false, true, false]`
- **IntegerArray**: `["42", "-123", "0"]` → `[42, -123, 0]`
- **EnumArray**: `["input", "output"]` → validated enum array
- **BinaryArray**: `["0x1a2b", "3c4d"]` → `[[0x1a, 0x2b], [0x3c, 0x4d]]`

### Comprehensive Error Handling

The system provides detailed error messages for debugging:

```rust
// Type mismatches
let result = bool_var.with("maybe");
// Error: "Cannot parse 'maybe' as boolean string (true/false, 1/0, yes/no, etc.)"

// Enum validation  
let result = power_var.with("invalid");
// Error: "Invalid enum option 'invalid', allowed: [low, medium, high]"

// Array size validation
let result = array_var.with(vec!["true", "false"]);  // Expected size: 4
// Error: "Array size mismatch: expected 4, got 2"

// Range validation
let result = preset_var.with("15");  // Max preset: 10
// Error: "Preset value 15 exceeds maximum 10"
```

## Builder Patterns

All types include builder patterns for clean construction:

```
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

```
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
        options: [ "low", "medium", "high" ]
```

## Dependencies

- `serde` with `derive` feature - for serialization support
- `serde_yaml` - for YAML format support
- `hex` - for binary data parsing and formatting

## Usage

Add to your `Cargo.toml` (assuming you're going into `common/`):

```toml
[dependencies]
mlxconfig_variables = { path = "../common/mlxconfig/variables" }
```

## Complete Example: `mlxconfig` JSON Integration

```rust
use mlxconfig_variables::*;
use mlxconfig_registry::registries;

fn process_mlx_response(json: &str) -> Result<Vec, Box> {
    let data: serde_json::Value = serde_json::from_str(json)?;
    let registry = registries::get("my_hardware_registry")?;
    let mut values = Vec::new();

    for (var_name, json_value) in data.as_object().unwrap() {
        if let Some(variable) = registry.get_variable(var_name) {
            let config_value = match json_value {
                serde_json::Value::String(s) => variable.with(s.clone())?,
                serde_json::Value::Array(arr) => {
                    let strings: Vec = arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect();
                    variable.with(strings)?
                }
                _ => continue,
            };

            println!("Parsed {}: {} ({})",
                     config_value.name(),
                     config_value,
                     format!("{:?}", config_value.spec())
            );

            values.push(config_value);
        }
    }

    Ok(values)
}
```

This crate is designed to be used by:

- **build.rs** to generate static registries at compile time
- **Runtime applications** that need to validate device compatibility
- **CLI tools** that work with configuration data
- **Libraries** that work with configuring Mellanox devices

## Architecture Notes

This crate is the foundation layer that provides:

1. **Type safety** through Rust's type system and compile-time validation
2. **Validation logic** for device constraints and value parsing
3. **Builder patterns** for ergonomic construction
4. **Serialization support** for persistence and interchange
5. **Zero-cost abstractions** with compile-time guarantees
6. **String parsing integration** for seamless `mlxconfig` JSON compatibility
7. **Context-aware conversion** that handles the same input differently based on variable specifications

The value creation system eliminates the need for manual type conversion and validation, providing a clean, intuitive
API that "just works" with both strongly-typed Rust values and string data from `mlxconfig` JSON responses.

The types defined here are consumed by `mlxconfig-registry` for compile-time embedding, as well as components like
the `forge-dpu-agent`, `scout`, and `carbide-api`.