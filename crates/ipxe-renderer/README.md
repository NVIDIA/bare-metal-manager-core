# carbide-ipxe-renderer

Template-based iPXE script renderer for Carbide Core operating system management.

## Overview

This crate provides a flexible, template-based approach to generating iPXE boot scripts for operating systems. It supports:

- Template-based iPXE script generation
- Parameter substitution with validation
- Potential artifact caching with local URL generation
- Deterministic hashing for change/tamper detection
- Required and reserved parameter enforcement
- Support for optional parameters if needed

## Features

### Core Components

- **`IpxeOsRenderer`**: Main trait for rendering iPXE scripts
- **`DefaultIpxeOsRenderer`**: Default implementation with built-in templates
- **Template Management**: Support for multiple iPXE script templates
- **Artifact Caching**: Local caching of remote artifacts (kernels, initrds, images)
- **Parameter Validation**: Validates required, reserved, and optional parameters

### Built-in Templates

1. **qcow-image**: Template for booting QCOW images using qcow-imager.efi
2. **ubuntu-autoinstall**: Template for Ubuntu autoinstall

## Usage

```rust
use carbide_ipxe_renderer::{
    IpxeOsRenderer, DefaultIpxeOsRenderer, IpxeOs, IpxeOsParameter, OsScope
};

// Create renderer
let renderer = DefaultIpxeOsRenderer::new();

// Define an iPXE OS
let mut ipxeos = IpxeOs {
    id: "test-os".to_string(),
    name: "Ubuntu 22.04".to_string(),
    ipxe_template_name: "qcow-image".to_string(),
    parameters: vec![
        IpxeOsParameter {
            name: "image_url".to_string(),
            value: "http://example.com/ubuntu.qcow2".to_string(),
        },
    ],
    // ... other fields
};

// Compute hash for validation
ipxeos.hash = renderer.hash(&ipxeos);

// Render iPXE script
let reserved_params = vec![
    IpxeOsParameter {
        name: "base_url".to_string(),
        value: "http://pxe.local".to_string(),
    },
    IpxeOsParameter {
        name: "console".to_string(),
        value: "ttyS0,115200".to_string(),
    },
];

let script = renderer.render(&ipxeos, &reserved_params)?;
```

## Testing

This crate is designed to be tested independently without platform-specific dependencies:

```bash
# Run all tests
cargo test --package carbide-ipxe-renderer

# Run specific test
cargo test --package carbide-ipxe-renderer test_hash_computation

# Run tests matching pattern
cargo test --package carbide-ipxe-renderer render

# Run with output
cargo test --package carbide-ipxe-renderer -- --nocapture
```

## Template System

### Parameters

Templates support three types of parameters:

1. **Required**: Must be provided in OS definition (e.g., `image_url`)
2. **Reserved**: Provided by carbide-core at render time (e.g., `base_url`, `console`)
3. **Optional**: Extra parameters replaced via `{{extra}}` placeholder

### Artifacts

Artifacts represent downloadable components (kernels, initrds, images):

```rust
IpxeOsArtifact {
    name: "kernel".to_string(),
    url: "http://example.com/vmlinuz".to_string(),
    sha: Some("sha256:abc123...".to_string()),
    cache_strategy: ArtifactCacheStrategy::CacheAsNeeded,
    local_url: Some("http://pxe.local/artifacts/kernel-abc123".to_string()),
}
```

### Validation

The renderer validates:
- Reserved parameters are NOT in OS definition
- Required parameters ARE present and non-empty
- Optional parameters only allowed if template has `{{extra}}`
- Hash matches computed hash

## Design

This implementation follows the design specified in `nvmetal/designs/designs/0076-Operating-System-Management-Move-to-Carbide-Core.md`.

## License

LicenseRef-NvidiaProprietary
