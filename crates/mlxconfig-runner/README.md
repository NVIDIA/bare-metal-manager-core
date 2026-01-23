# mlxconfig-runner

High-level Rust wrapper around the `mlxconfig` CLI tool with type-safe, registry-driven
configuration management for Mellanox devices using mlxconfig-registry and mlxconfig-variables.

## Features

🚀 **Smart Configuration Management**

- Intelligent sync operations that only change what's different.
- Compare operations for dry-run analysis and state verification.
- Automatic array handling (complete and sparse operations).

🎯 **Unified APIs**

- Single methods that accept multiple input types via traits.
- String-based API for convenience: `("VAR_NAME", value)`.
- Type-safe API for production: `Vec<MlxConfigValue>`.
- Automatic variable name resolution from registries.

🛡️ **Production Ready**

- Comprehensive error handling with detailed context.
- Configurable timeouts, retries, and confirmation prompts.
- Extensive logging and dry-run capabilities.
- Zero runtime parsing overhead (compile-time registry embedding).

⚙️ **Array Support**

- Complete array operations: set entire arrays at once.
- "Sparse" array operations: set individual indices only.
- Automatic expansion for queries: `ARRAY[0..size]`.
- Index syntax support: `"ARRAY_VAR[2]"` → sparse array.

🔒 **Device Filter Validation**

- Registry compatibility checking (device type, part number, firmware version).
- Compile-time device filter validation prevents incompatible configurations.
- Detailed validation error reporting.

## Quick Start

### Basic Usage

```rust
use mlxconfig_runner::*;
use mlxconfig_registry::registries;

// Create runner with a device and registry
let registry = registries::get("mlx_generic").unwrap();
let runner = MlxConfigRunner::new("01:00.0".to_string(), registry.clone());

// Query all variables defined in the registry
let result = runner.query_all()?;
println!("Found {} variables", result.variable_count());

// Inspect query results
for var in &result.variables {
    println!("{}: current={}, next={}, modified={}",
             var.name(), var.current_value, var.next_value, var.modified);

    if var.is_pending_change() {
        println!("  → Pending change detected!");
    }
}

// Set variables using the convenient string API
runner.set(&[
    ("SRIOV_EN", true),
    ("NUM_OF_VFS", 16),
    ("INTERNAL_CPU_OFFLOAD_ENGINE", "ENABLED"),
    ("PCI_DOWNSTREAM_PORT_OWNER[0]", "HOST_1"),    // Individual index (sparse)
    ("PCI_DOWNSTREAM_PORT_OWNER[5]", "EMBEDDED_CPU"), // Another sparse index
])?;

// Smart sync: only changes what's different
let sync_result = runner.sync(&[
    ("SRIOV_EN", false),
    ("NUM_OF_VFS", 32),
])?;
println!("Changed {}/{} variables",
         sync_result.variables_changed,
         sync_result.variables_checked);
```

### Advanced Configuration

```rust
use std::time::Duration;

// Create runner with custom execution options
let options = ExecOptions::default()
    .with_timeout(Some(Duration::from_secs(60)))
    .with_retries(3)
    .with_verbose(true)
    .with_confirm_destructive(true);

let mut runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);
runner.set_temp_file_prefix("/custom/tmp");

// Type-safe API with pre-built values
let sriov_var = registry.get_variable("SRIOV_EN").unwrap();
let config_values = vec![
    sriov_var.with(true)?,  // Type-safe value creation
];
runner.set(config_values)?;

// Dry-run analysis without making changes
let comparison = runner.compare(&[("NUM_OF_VFS", 64)])?;
for change in &comparison.planned_changes {
    println!("Would change: {}", change.description());
}
```

### Flexible Input Types via Traits

```rust
// Multiple input types supported for queries
runner.query(&["SRIOV_EN", "NUM_OF_VFS"])?;           // &[&str]
runner.query(vec!["SRIOV_EN".to_string()])?;          // Vec<String>
runner.query(["SRIOV_EN", "NUM_OF_VFS"])?;            // Arrays of any size

// Multiple input types supported for set/sync operations
runner.set(&[("SRIOV_EN", true)])?;                   // &[(&str, T)]
runner.set(vec![config_value])?;                      // Vec<MlxConfigValue>
runner.set([("SRIOV_EN", false)])?;                   // Arrays of any size
runner.set(vec![("SRIOV_EN".to_string(), "true".to_string())])?; // Vec<(String, String)>
```

### Array Operations

```rust
// Complete array setting (must match registry-defined size)
let array_var = registry.get_variable("PCI_DOWNSTREAM_PORT_OWNER").unwrap();
// This variable has size=16 in the registry
runner.set(vec![array_var.with(vec!["HOST_0"; 16])?])?;

// Sparse array setting (only specific indices) using Vec<Option<T>>
let sparse_value = array_var.with(vec![
    Some("HOST_1".to_string()),    // [0] = HOST_1
    None,                          // [1] = unchanged
    None,                          // [2] = unchanged  
    Some("EMBEDDED_CPU".to_string()), // [3] = EMBEDDED_CPU
    None,                          // [4] = unchanged
    // ... remaining 11 indices = None (unchanged)
    None, None, None, None, None, None, None, None, None, None, None,
])?;
runner.set(vec![sparse_value])?;

// String API also supports array indices
runner.set(&[
    ("PCI_DOWNSTREAM_PORT_OWNER[0]", "HOST_2"),
    ("PCI_DOWNSTREAM_PORT_OWNER[3]", "HOST_1"),
    ("PCI_DOWNSTREAM_PORT_OWNER[15]", "EMBEDDED_CPU"),
])?;

// Query specific array indices
runner.query(&["PCI_DOWNSTREAM_PORT_OWNER[0]", "PCI_DOWNSTREAM_PORT_OWNER[3]"])?;
```

## Architecture

The runner provides a clean, high-level interface to `mlxconfig` operations:

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  mlxconfig-runner   │    │  mlxconfig-registry │    │  mlxconfig-variables│
│                     │    │                     │    │                     │
│  • MlxConfigRunner  │◄───┤  • Static registries│◄───┤  • Core types       │
│  • ExecOptions      │    │  • Build-time embed │    │  • Value conversion │
│  • Query/Set/Sync   │    │  • Device filters   │    │  • Validation logic │
│  • Array handling   │    │  • YAML → Rust      │    │  • Builder patterns │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
           │
           ▼
    ┌─────────────┐
    │   mlxconfig │  (External CLI tool)
    │ (sudo req.) │
    └─────────────┘
```

## Command Generation

The runner generates efficient `mlxconfig` commands:

### Query Commands

```bash
# Query specific variables (arrays auto-expanded)
sudo mlxconfig -d 01:00.0 -e -j /tmp/mlxconfig-runner-uuid.json q SRIOV_EN NUM_OF_VFS PCI_DOWNSTREAM_PORT_OWNER[0..15]

# Query specific array indices
sudo mlxconfig -d 01:00.0 -e -j /tmp/mlxconfig-runner-uuid.json q PCI_DOWNSTREAM_PORT_OWNER[0] PCI_DOWNSTREAM_PORT_OWNER[3]
```

### Set Commands

```bash
# Batch variable setting
sudo mlxconfig -d 01:00.0 --yes set SRIOV_EN=true NUM_OF_VFS=16 INTERNAL_CPU_OFFLOAD_ENGINE=ENABLED

# Sparse array setting (only changed indices)
sudo mlxconfig -d 01:00.0 --yes set PCI_DOWNSTREAM_PORT_OWNER[0]=HOST_1 PCI_DOWNSTREAM_PORT_OWNER[15]=EMBEDDED_CPU

# Complete array setting
sudo mlxconfig -d 01:00.0 --yes set PCI_DOWNSTREAM_PORT_OWNER[0]=HOST_0 PCI_DOWNSTREAM_PORT_OWNER[1]=HOST_0 ... PCI_DOWNSTREAM_PORT_OWNER[15]=HOST_0
```

## Comprehensive Error Handling

Detailed error types with rich context information:

```rust
match runner.set(&[("INVALID_VAR", 42)]) {
    Err(MlxRunnerError::VariableNotFound { variable_name }) => {
        println!("Variable '{variable_name}' not found in registry");
    }
    Err(MlxRunnerError::ArraySizeMismatch { variable_name, expected, found }) => {
        println!("Array '{variable_name}' size mismatch: expected {expected}, got {found}");
    }
    Err(MlxRunnerError::ValueConversion { variable_name, value, error }) => {
        println!("Failed to convert '{value}' for variable '{variable_name}': {error}");
    }
    Err(MlxRunnerError::CommandExecution { command, stderr, exit_code, .. }) => {
        println!("Command failed: {command}\nExit code: {exit_code:?}\nError: {stderr}");
    }
    Err(MlxRunnerError::Timeout { command, duration }) => {
        println!("Command timed out after {duration:?}: {command}");
    }
    Err(MlxRunnerError::ConfirmationDeclined { variables }) => {
        println!("User declined destructive operation for variables: {variables:?}");
    }
    Ok(_) => println!("Success!"),
}
```

## Integration with Registry System

Works seamlessly with the compile-time registry system:

```rust
// Registries are embedded at compile time from YAML files
use mlxconfig_registry::registries;

// List all available registries
println!("Available registries: {:?}", registries::list());

// Get registry for specific hardware
let registry = registries::get("mlx_generic")?;
println!("Registry '{}' has {} variables", registry.name, registry.variables.len());

// Runner automatically knows variable types and device filters.
let runner = MlxConfigRunner::new("01:00.0".to_string(), registry.clone());

// Array variables are automatically detected and expanded
runner.query(&["PCI_DOWNSTREAM_PORT_OWNER"])?; // Expands to [0..15] based on registry
```

## Execution Options

Fine-grained control over command execution:

```rust
let options = ExecOptions::default()
    .with_timeout(Some(Duration::from_secs(60)))      // Command timeout
    .with_retries(3)                                  // Retry failed commands  
    .with_retry_delay(Duration::from_millis(500))     // Initial delay between retries
    .with_max_retry_delay(Duration::from_secs(60))    // Maximum retry delay (exponential backoff)
    .with_retry_multiplier(2.0)                       // Exponential backoff multiplier
    .with_dry_run(true)                               // Log without executing
    .with_verbose(true)                               // Log all commands and operations
    .with_log_json_output(true)                       // Log raw JSON responses  
    .with_confirm_destructive(true);                  // Prompt for destructive variables

let runner = MlxConfigRunner::with_options("01:00.0".to_string(), registry, options);
```

## Available Registries

Current embedded registries (from `databases/*.yaml`):

- **`mlx_generic`**: Generic Mellanox device configuration variables
  - Variables: `SRIOV_EN`, `NUM_OF_VFS`, `HIDE_PORT2_PF`, `NUM_OF_PF`, `INTERNAL_CPU_OFFLOAD_ENGINE`, `ROCE_ADAPTIVE_ROUTING_EN`, and more
  - Includes array variables like `PCI_DOWNSTREAM_PORT_OWNER[16]`
  - Supports boolean, integer, enum, and enum array types

## Registry Variable Types

The system supports rich variable types with automatic validation:

```rust
// Boolean variables
runner.set(&[("SRIOV_EN", true)])?;
runner.set(&[("ROCE_ADAPTIVE_ROUTING_EN", false)])?;

// Integer variables  
runner.set(&[("NUM_OF_VFS", 16)])?;
runner.set(&[("ROCE_RTT_RESP_DSCP_P1", 42)])?;

// Enum variables (validated against registry options)
runner.set(&[("INTERNAL_CPU_OFFLOAD_ENGINE", "ENABLED")])?; // Options: ["ENABLED", "DISABLED"]
runner.set(&[("MULTIPATH_DSCP", "DSCP_1")])?; // Options: ["DEVICE_DEFAULT", "DISABLE", "DSCP_0", "DSCP_1", "DSCP_2"]

// Enum arrays (each element validated)
runner.set(&[("PCI_DOWNSTREAM_PORT_OWNER", vec!["HOST_0", "HOST_1", "EMBEDDED_CPU"])])?;

// Read-only variables (detected and prevented)
// USER_PROGRAMMABLE_CC is read-only in the registry - attempts to set will fail
```

## Requirements

- **mlxconfig CLI tool** must be installed and accessible via `PATH`
- **sudo privileges** for hardware access (users manage sudo, not the runner)
- **mlxconfig-registry** and **mlxconfig-variables** crates for type definitions
- **Rust 2021 edition** or later

## Safety Features

- **Compile-time validation**: Invalid configs cause build failures
- **Type safety**: All values validated against registry specs  
- **Array bounds checking**: Automatic size validation for all array operations
- **Enum validation**: All enum values checked against registry-defined options
- **Destructive variable protection**: Optional confirmation prompts for dangerous operations
- **Device filter validation**: Registry compatibility checking prevents misconfigurations
- **Comprehensive error handling**: Detailed context for all failure modes with retry logic
- **Dry-run support**: Test operations without making changes
- **Exponential backoff**: Intelligent retry behavior for transient failures

## Production Deployment

This crate is designed for production hardware management:

- **Zero runtime parsing**: All registry data embedded at compile time
- **Minimal allocations**: Efficient command generation and response parsing  
- **Robust error handling**: Graceful degradation and detailed error reporting
- **Extensive logging**: Comprehensive audit trail for compliance and debugging
- **Configurable timeouts**: Prevents hanging operations in production environments
- **Registry device filters**: Ensures configurations are only applied to compatible hardware

Perfect for integration into:
- Hardware provisioning systems
- Configuration management tools  
- Device monitoring and alerting
- Automated testing frameworks
- Production deployment pipelines
