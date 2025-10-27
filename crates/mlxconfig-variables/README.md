# mlxconfig_variables

Core type definitions and validation logic for Mellanox hardware configuration.

## Overview

The `mlxconfig_variables` crate provides the foundational types and validation logic used throughout our little
`mlxconfig` configuration ecosystem. This crate defines the data structures for hardware configuration variables, device
filters, and registries, along with builder patterns for easy construction and a powerful value creation system for
working with actual configuration data.

## Key Components

### Configuration Variables (`MlxConfigVariable`)

Represents a single hardware configuration parameter with:

- **Name**: Unique identifier for the variable
- **Description**: Human-readable description
- **Read-only flag**: Whether the variable can be modified
- **Spec**: Type specification defining the variable's data type and device filters

### Variable Specifications (`MlxVariableSpec`)

Strongly-typed enum defining all supported variable types:

- **Simple types**: `Boolean`, `Integer`, `String`, `Binary`, `Bytes`, `Array`, `Opaque`
- **Enum types**: `Enum { options }` - choice from predefined values
- **Preset types**: `Preset { max_preset }` - numbered presets (0 to max)
- **Array types**: `BooleanArray`, `IntegerArray`, `BinaryArray` - fixed-size arrays with sparse support
- **Complex arrays**: `EnumArray` - arrays of enum values with sparse support

### Configuration Values (`MlxConfigValue`)

Typed values that pair configuration variables with their actual data:

- **Variable**: The configuration variable definition
- **Value**: Strongly-typed value that matches the variable's spec
- **Validation**: Automatic type and device filter validation
- **Display**: Built-in formatting for user interfaces

### Sparse Array Support

All array types (`BooleanArray`, `IntegerArray`, `EnumArray`, `BinaryArray`) support **sparse arrays** where individual
indices can be unset (`None`). This enables partial configuration updates where only specific array positions need to be
modified while leaving others unchanged.

**Key benefits:**

- **Partial updates**: Configure only specific array indices without affecting others
- **Efficient storage**: Unset values don't consume unnecessary space
- **Clear semantics**: `None` explicitly indicates "no value set" vs. a default value
- **Flexible input**: Accept both dense arrays (converted automatically) and explicit sparse arrays

### Hardware Registries (`MlxVariableRegistry`)

Collections of related configuration variables with optional device filters:

- **Name**: Registry identifier
- **Variables**: List of configuration variables
- **Filters**: Optional device compatibility rules

### Device Filters (`DeviceFilter` & `DeviceFilterSet`)

Define which hardware devices can use specific registries:

- **Device types**: e.g., "Bluefield3", "ConnectX-7"
- **Part numbers**: e.g., "900-9D3D4-00EN-HA0"
- **Firmware versions**: e.g., "32.41.130"

### Device Information (`MlxDeviceInfo`)

Container for actual device details used in filter validation.

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
let array_value = bool_array_var.with(vec![true, false]) ?; // Boolean array (dense)

// Display values
println!("Turbo: {}", turbo_value);     // "true"
println!("Frequency: {}", freq_value);  // "2400"
println!("Power: {}", power_value);     // "high"
```

### Sparse Array Creation

Arrays support both dense and sparse formats:

```rust
use mlxconfig_variables::*;

let gpio_var = registry.get_variable("gpio_modes").unwrap(); // EnumArray { size: 8 }

// Dense array - all positions set (automatically converted to sparse format internally)
let dense_value = gpio_var.with(vec![
    "input", "output", "input", "output",
    "input", "output", "input", "output"
]) ?;

// Sparse array - only some positions set
let sparse_value = gpio_var.with(vec![
    Some("input".to_string()),
    None,                    // Position 1 unset
    Some("output".to_string()),
    None,                    // Position 3 unset  
    Some("input".to_string()),
    None, None, None         // Positions 5-7 unset
]) ?;

// String parsing with sparse notation
let from_strings = gpio_var.with(vec![
    "input", "-", "output", "",  // "-" or empty means None
    "input", "-", "-", "-"
]) ?;

// Display shows unset positions as "-"
println!("{}", sparse_value); // "[input, -, output, -, input, -, -, -]"
```

### String Parsing for `mlxconfig` JSON Integration

The system natively handles string input from `mlxconfig` JSON responses, with automatic parsing based on
variable types:

```rust
// From JSON - everything comes as strings
let json_response = r#"{
  "enable_turbo": "true",
  "cpu_frequency": "2400", 
  "power_mode": "high",
  "gpio_modes": ["input", "-", "output", "bidirectional", "-", "-", "-", "-"]
}"#;

let data: serde_json::Value = serde_json::from_str(json_response) ?;
let registry = registries::get("my_registry").unwrap();

// Process JSON values
for (var_name, json_value) in data.as_object().unwrap() {
if let Some(variable) = registry.get_variable(var_name) {
let config_value = match json_value {
// Single string values - automatic type conversion.
serde_json::Value::String(s) => {
variable.with(s.clone())?  // Boolean, Integer, Enum, etc.
}

// Array values - parse each string element, handle sparse notation.
serde_json::Value::Array(arr) => {
let strings: Vec < String > = arr.iter()
.filter_map( | v | v.as_str())
.map(String::from)
.collect();
variable.with(strings) ?  // Sparse arrays supported
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

#### Array Variables (with Sparse Support)

- **BooleanArray**: `["true", "0", "-", "disabled"]` → `[Some(true), Some(false), None, Some(false)]`
- **IntegerArray**: `["42", "-", "0"]` → `[Some(42), None, Some(0)]`
- **EnumArray**: `["input", "", "output"]` → `[Some("input"), None, Some("output")]`
- **BinaryArray**: `["0x1a2b", "-", "3c4d"]` → `[Some([0x1a, 0x2b]), None, Some([0x3c, 0x4d])]`

**Sparse Array Notation:**

- `"-"` (dash) indicates an unset position (`None`)
- `""` (empty string) also indicates an unset position (`None`)
- Any other value is parsed according to the array element type

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

// Sparse array enum validation
let result = enum_array_var.with(vec![Some("valid".to_string()), Some("invalid".to_string())]);
// Error: "Invalid enum option 'invalid' at position 1, allowed: [valid, other]"
```

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

// Build a sparse-capable enum array variable
let gpio_modes = MlxConfigVariable::builder()
.name("gpio_pin_modes")
.description("GPIO pin mode configuration")
.read_only(false)
.spec(
MlxVariableSpec::builder()
.enum_array()
.with_options(vec!["input", "output", "bidirectional"])
.with_size(8)  // 8 positions, some may be unset
.build()
)
.build();
```

## YAML Serialization

All types support serde serialization for YAML configuration files:

```yaml
name: "example_registry"
variables:
  - name: "cpu_frequency"
    description: "CPU frequency in MHz"
    read_only: false
    spec:
      type: "integer"
  - name: "gpio_pin_modes"
    description: "GPIO pin mode configuration (supports sparse arrays)"
    read_only: false
    spec:
      type: "enum_array"
      config:
        options: [ "input", "output", "bidirectional" ]
        size: 8
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

## Complete Example: `mlxconfig` JSON Integration with Sparse Arrays

```rust
use mlxconfig_variables::*;
use mlxconfig_registry::registries;

fn process_mlx_response(json: &str) -> Result<Vec<MlxConfigValue>, Box<dyn std::error::Error>> {
    let data: serde_json::Value = serde_json::from_str(json)?;
    let registry = registries::get("my_hardware_registry")?;
    let mut values = Vec::new();

    for (var_name, json_value) in data.as_object().unwrap() {
        if let Some(variable) = registry.get_variable(var_name) {
            let config_value = match json_value {
                serde_json::Value::String(s) => variable.with(s.clone())?,
                serde_json::Value::Array(arr) => {
                    let strings: Vec<String> = arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect();
                    variable.with(strings)?  // Supports sparse arrays via "-" notation
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

// Example JSON with sparse array data
let json = r#"{
    "enable_turbo": "true",
    "gpio_modes": ["input", "-", "output", "", "bidirectional", "-", "-", "-"],
    "sensor_readings": ["42", "38", "-", "41", "-", "39"]
}"#;

let values = process_mlx_response(json) ?;
// gpio_modes becomes: [Some("input"), None, Some("output"), None, Some("bidirectional"), None, None, None]
// sensor_readings becomes: [Some(42), Some(38), None, Some(41), None, Some(39)]
```

## Architecture Notes

This crate is the foundation layer that provides:

1. **Type safety** through Rust's type system and compile-time validation
2. **Validation logic** for device filters and value parsing
3. **Builder patterns** for ergonomic construction
4. **Serialization support** for persistence and interchange
5. **Zero-cost abstractions** with compile-time guarantees
6. **String parsing integration** for seamless `mlxconfig` JSON compatibility
7. **Context-aware conversion** that handles the same input differently based on variable specifications
8. **Sparse array support** for efficient partial configuration updates

The value creation system eliminates the need for manual type conversion and validation, providing a clean, intuitive
API that "just works" with both strongly-typed Rust values and string data from `mlxconfig` JSON responses. The sparse
array feature enables efficient partial updates where only specific array indices need modification, making it ideal
for hardware configuration scenarios where you want to change specific settings without affecting others.

The types defined here are consumed by `mlxconfig-registry` for compile-time embedding, as well as components like
the `forge-dpu-agent`, `scout`, and `carbide-api`.
