# mlxconfig-profile

Profile-based configuration management for working with mlxconfig-managed devices

## Overview

The `mlxconfig-profile` crate provides a high-level abstraction for managing `mlsconfig`-based configurations through
reusable profiles. It pulls together mlxconfig-variables, mlxconfig-registry, and mlxconfig-runner to profile a simple
way to define, compare, and sync expected configuration to devices (and monitor the current state).

## Key Features

### ✅ **Profile Builder API**

```
let profile = MlxConfigProfile::new("my_config", registry)
  .with_description("SR-IOV configuration")
  .with("SRIOV_EN", true)?
  .with("NUM_OF_VFS", 16)?
  .with("PCI_DOWNSTREAM_PORT_OWNER", vec!["HOST_0", "HOST_0", "-", "-", "-", "-", "-", "-", "EMBEDDED_CPU"])?;

// Direct device operations
let comparison = profile.compare("01:00.0", None)?;
let sync_result = profile.sync("01:00.0", None)?;
```

### ✅ **Profile YAML Format**

```yaml
name: "sriov_config"
registry_name: "mlx_generic"
description: "SR-IOV enabled configuration"
config:
  SRIOV_EN: true
  NUM_OF_VFS: 16
  NUM_OF_PF: 2
  INTERNAL_CPU_OFFLOAD_ENGINE: "ENABLED"
  # Sparse arrays with "-" for None values
  PCI_DOWNSTREAM_PORT_OWNER: [ "HOST_0", "HOST_0", "-", "-", "-", "-", "-", "-", "EMBEDDED_CPU", "-", "-", "-", "-", "-", "-", "HOST_1" ]
```

### ✅ **Automatic Type Conversion**

- **YAML → Profile**: `IntoMlxValue for serde_yaml::Value` handles all conversion.
- **Profile → YAML**: `MlxValueType::to_yaml_value()` extracts clean values.
- **Registry Validation**: All variables validated against registry specs.
- **Filter Checking**: Device compatibility verified before operations.

### ✅ **No Custom Parsing**

- Leverages existing `IntoMlxValue` trait implementations.
- No duplicate conversion logic.
- Sparse arrays handled automatically via `"-"` markers.
- All validation in the type system.

## Architecture

```
Profile Creation:
YAML Values → (IntoMlxValue trait) → MlxValueType → MlxConfigValue → Profile

Profile Serialization:  
Profile → MlxConfigValue → (to_yaml_value method) → YAML Values → File

Device Operations:
Profile → (MlxConfigRunner) → mlxconfig CLI → Device
```

## Core Implementation

### Profile Structure

```
pub struct MlxConfigProfile {
    pub name: String,
    pub registry: MlxVariableRegistry,
    pub description: Option<String>,
    pub config_values: Vec<MlxConfigValue>,
    // Internal lookup map for efficient access
}
```

### Unified API

```
impl MlxConfigProfile {
    // Single method for all types - leverages IntoMlxValue.
    pub fn with<T: IntoMlxValue>(variable_name: &str, value: T) -> Result<Self, Error>
    
    // For pre-built values.
    pub fn with_config_value(config_value: MlxConfigValue) -> Result<Self, Error>
    
    // Direct device operations.
    pub fn compare(device: &str, options: Option<ExecOptions>) -> Result<ComparisonResult, Error>
    pub fn sync(device: &str, options: Option<ExecOptions>) -> Result<SyncResult, Error>
}
```

### Serialization Integration

```
// Loading from YAML.
pub fn to_profile(self) -> Result<MlxConfigProfile, Error> {
    for (variable_name, yaml_value) in self.config {
        profile = profile.with(&variable_name, yaml_value)?;
    }
    Ok(profile)
}

// Saving to YAML.
fn config_value_to_yaml_value(config_value: &MlxConfigValue) -> Result<serde_yaml::Value, Error> {
    Ok(config_value.value.to_yaml_value())
}
```

## Usage Examples

### Programmatic Creation

```
use mlxconfig_profile::MlxConfigProfile;

let registry = mlxconfig_registry::registries::get("mlx_generic").unwrap().clone();

let profile = MlxConfigProfile::new("some_profile", registry)
    .with_description("Maximum throughput configuration")
    .with("SRIOV_EN", false)?
    .with("NUM_OF_VFS", 0)?
    .with("INTERNAL_CPU_OFFLOAD_ENGINE", "ENABLED")?
    .with("TX_SCHEDULER_LOCALITY_MODE", "STATIC_MODE")?;

// Apply to device.
let sync_result = profile.sync("01:00.0", None)?;
println!("Applied {} changes", sync_result.variables_changed);
```

### YAML-Based Configuration

```
let yaml_content = r#"
name: "production_config"
registry_name: "mlx_generic"
description: "Production-ready configuration"
config:
  SRIOV_EN: true
  NUM_OF_VFS: 32
  NUM_OF_PF: 4
  INTERNAL_CPU_OFFLOAD_ENGINE: "ENABLED"
  ROCE_ADAPTIVE_ROUTING_EN: true
  PCI_DOWNSTREAM_PORT_OWNER: ["HOST_0", "HOST_0", "HOST_1", "HOST_1", "-", "-", "-", "-", "EMBEDDED_CPU"]
"#;

let profile = MlxConfigProfile::from_yaml_str(yaml_content)?;

// Compare against current device state.
let comparison = profile.compare("01:00.0", None)?;
for change in &comparison.planned_changes {
    println!("Would change: {}", change.description());
}
```

### Array Handling

```
// Dense arrays.
profile.with("SOME_ARRAY", vec!["val1", "val2", "val3", "val4"])?

// Sparse arrays (using "-" for None).
profile.with("PCI_DOWNSTREAM_PORT_OWNER", vec![
    "HOST_0", "HOST_0", "-", "-", "-", "-", "-", "-", 
    "EMBEDDED_CPU", "-", "-", "-", "-", "-", "-", "HOST_1"
])?

// Or build sparse arrays programmatically.
let mut sparse = vec![None; 16];
sparse[0] = Some("HOST_0".to_string());
sparse[1] = Some("HOST_0".to_string());
sparse[8] = Some("EMBEDDED_CPU".to_string());
sparse[15] = Some("HOST_1".to_string());
profile.with("PCI_DOWNSTREAM_PORT_OWNER", sparse)?
```

## File Operations

### Save and Load

```
// Save profile.
profile.to_yaml_file("configs/dpa.yaml")?;
profile.to_json_file("configs/dpa.json")?;

// Load profile  .
let profile = MlxConfigProfile::from_yaml_file("configs/dpu.yaml")?;
let profile = MlxConfigProfile::from_json_file("configs/dpu.json")?;

// String conversion.
let yaml_string = profile.to_yaml_string()?;
let json_string = profile.to_json_string()?;
```

## Device Operations

### Configuration Options

```
use mlxconfig_runner::ExecOptions;

let options = ExecOptions::default()
    .with_timeout(Some(Duration::from_secs(60)))
    .with_retries(3)
    .with_verbose(true)
    .with_dry_run(false);

// Compare what would change.
let comparison = profile.compare("01:00.0", Some(options.clone()))?;
println!("Variables needing change: {}", comparison.variables_needing_change);

// Apply changes.
let sync_result = profile.sync("01:00.0", Some(options))?;
println!("Applied {} changes in {:?}", 
         sync_result.variables_changed, 
         sync_result.execution_time);
```

## Error Handling

```
use mlxconfig_profile::MlxProfileError;

match profile.sync("01:00.0", None) {
    Ok(result) => println!("Success: {}", result.summary()),
    Err(MlxProfileError::RegistryNotFound { registry_name }) => {
        println!("Registry '{}' not found", registry_name);
    }
    Err(MlxProfileError::VariableNotFound { variable_name, registry_name }) => {
        println!("Variable '{}' not in registry '{}'", variable_name, registry_name);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Key Design Insights

### ✅ **Registry-Driven Validation**

Profiles are backed by registries that define available variables, types, and device filters. All validation happens
through the type system.

### ✅ **Unified API**

Single `.with()` method accepts any `T: IntoMlxValue`. No need for separate methods for different input types.

### ✅ **Clean Separation**

- **Profile**: High-level operations and validation
- **SerializableProfile**: YAML/JSON handling
- **MlxValueType**: Core conversion logic
- **Traits**: Reusable conversion implementations systems.