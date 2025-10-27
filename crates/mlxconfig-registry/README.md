# mlxconfig_registry

Compile-time registry generation and access for Mellanox hardware configuration.

## Overview

The `mlxconfig_registry` crate provides compile-time generation of hardware configuration registries from YAML files. During the build process, it validates YAML configuration files and embeds them as static data structures in the compiled binary, providing zero runtime parsing overhead and compile-time guarantees of variables to use with `mlxconfig`.

## How It Works

```
YAML Files → build.rs → Generated `registries.rs` → REGISTRIES constant
```

1. **Build Time**: `build.rs` scans `databases/*.yaml` files
2. **Validation**: Each YAML file is parsed and validated as a complete `MlxVariableRegistry`
3. **Code Generation**: Static Rust code is generated using builder patterns
4. **Embedding**: Validated data becomes a static `REGISTRIES` constant
5. **Runtime**: Applications access pre-validated, zero-cost static data

## Directory Structure

```
mlxconfig_registry/
├── Cargo.toml
├── build.rs                 # Compile-time YAML processor & code generator
├── databases/               # YAML configuration files
│   ├── registry-bf3.yaml    # Examples of individual database files.
│   └── registry-cx7.yaml
└── src/
    ├── lib.rs               # Public API exports.
    └── registries.rs        # Auto-generated (do not edit manually).
```

## YAML Configuration Format

### Simple Variables
```yaml
name: "basic_hardware_registry"
variables:
  - name: "cpu_frequency"
    description: "CPU frequency in MHz"
    read_only: false
    spec:
      type: "integer"

  - name: "enable_turbo"
    description: "Enable CPU turbo mode"
    read_only: false
    spec:
      type: "boolean"
```

### Complex Variables with Configuration
```yaml
name: "advanced_hardware_registry"
variables:
  - name: "power_mode"
    description: "Power management mode"
    read_only: false
    spec:
      type: "enum"
      config:
        options: ["low", "medium", "high", "turbo"]

  - name: "gpio_modes"
    description: "GPIO pin configurations"
    read_only: false
    spec:
      type: "enum_array"
      config:
        options: ["input", "output", "bidirectional"]
        size: 8
```

## Generated Code Structure

The build process generates `src/registries.rs` with:

```rust
// Auto-generated - do not edit manually
use once_cell::sync::Lazy;

pub static REGISTRIES: Lazy<Vec<mlxconfig_variables::MlxVariableRegistry>> =
    Lazy::new(|| vec![
        // Builder pattern construction for each registry...
    ]);

/// Access functions
pub fn get_all() -> &'static [mlxconfig_variables::MlxVariableRegistry] { /* ... */ }
pub fn get(name: &str) -> Option<&'static mlxconfig_variables::MlxVariableRegistry> { /* ... */ }
pub fn list() -> Vec<&'static str> { /* ... */ }
```

## Runtime Usage

### Basic Access
```rust
use mlxconfig_registry::registries;

// Get all registries
for registry in registries::get_all() {
    println!("Registry: {}", registry.name);
    println!("Variables: {}", registry.variables.len());
}

// Get specific registry by name
if let Some(registry) = registries::get("bluefield3_registry") {
    println!("Found registry with {} variables", registry.variables.len());
}

// List all registry names
let names = registries::list();
println!("Available registries: {:?}", names);
```

## Build Process Details

### Build Script Workflow
1. **Discovery**: Scans `databases/*.yaml` for configuration files
2. **Parsing**: Each file is deserialized as `MlxVariableRegistry` using serde
3. **Validation**: Build fails if any YAML file is malformed or invalid
4. **Generation**: Creates `src/registries.rs` with builder pattern code
5. **Embedding**: Data becomes compile-time constants with zero runtime cost

### Build Output Example
```bash
$ cargo build
warning: mlxconfig_registry@0.1.0: [INFO] Parsed registry 'bluefield3_registry' with 6 variables from registry-bf3
warning: mlxconfig_registry@0.1.0: [INFO] Parsed registry 'connectx7_registry' with 4 variables from registry-cx7
warning: mlxconfig_registry@0.1.0: [INFO] Generated 2 registries with 10 total variables
   Compiling mlxconfig_registry v0.1.0
   Finished dev [unoptimized + debuginfo] target(s)
```

### Build Error Handling
- **Invalid YAML**: Build fails with precise error location
- **Missing fields**: Serde validation catches incomplete definitions
- **Type errors**: Rust compiler validates all generated code
- **Device filter conflicts**: Logical validation during parsing

## Key Benefits

### Compile-Time Safety
- **Impossible to ship bad configs**: Build fails on invalid YAML
- **Type validation**: All fields required, types verified at build time
- **Zero runtime failures**: All errors caught before deployment

### Performance
- **Zero parsing overhead**: Data embedded as static structures
- **Memory efficient**: No dynamic allocation for config data
- **Fast startup**: No file I/O or YAML parsing at runtime
- **Optimal for embedded**: Perfect for hardware management systems

### Developer Experience
- **Clean APIs**: Generated builder patterns provide intuitive interfaces
- **IDE support**: Full autocomplete and type checking available
- **Readable errors**: Build failures point directly to YAML issues
- **Debuggable**: Generated code is inspectable in `src/registries.rs`

## Dependencies

### Runtime Dependencies
- `once_cell` - for lazy static initialization
- `mlxconfig_variables` - core type definitions

### Build Dependencies
- `serde` with `derive` feature - YAML deserialization
- `serde_yaml` - YAML parsing
- `mlxconfig_variables` - type definitions for build script

## Adding New Registries

1. **Create YAML file**: Add `databases/my-new-registry.yaml`
2. **Define structure**: Follow the YAML format documented above
3. **Build**: Run `cargo build` to validate and generate code
4. **Access**: Use `registries::get("my-new-registry")` to access at runtime

## Integration

Add to your `Cargo.toml`:

```toml
[dependencies]
mlxconfig_registry = { path = "../mlxconfig_registry" }
```

This crate is designed for:
- **Hardware management applications** needing device-specific configurations
- **Embedded systems** requiring zero-overhead config access
- **CLI tools** that work with hardware registries
- **Libraries** that extend MLX device functionality

The compile-time approach ensures that configuration errors are caught during development rather than in production, making it ideal for mission-critical hardware management systems.
