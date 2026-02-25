# iPXE Template Configuration

## Overview

The `DefaultIpxeOsRenderer` now loads iPXE script templates from a YAML configuration file at compile time. This makes it easier to manage, update, and version control the templates without modifying Rust code.

## Files

- **`templates.yaml`**: Contains all iPXE script template definitions
- **`src/lib.rs`**: Loads and parses the YAML at compile time using `include_str!`

## Template Structure

Each template in `templates.yaml` has the following structure:

```yaml
templates:
  - name: template-name
    description: Human-readable description
    required_params:
      - param1
      - param2
    reserved_params:
      - reserved1
      - reserved2
    template: |
      #!ipxe
      # Template content with {{param}} placeholders
```

## Fields

- **name**: Unique identifier for the template (used in API calls)
- **description**: Human-readable description of what the template does
- **required_params**: List of parameters that must be provided by the user
- **reserved_params**: Parameters that are provided by the system (base_url, console, etc.)
- **template**: The actual iPXE script with `{{parameter}}` placeholders

## Current Templates

1. **raw-ipxe**: Raw iPXE scripting with base_url, console, and arch variables
2. **qcow-image**: Boots qcow disk images using the qcow-imager.efi tool
3. **ubuntu-autoinstall**: Ubuntu autoinstall using kernel, initrd, and install ISO
4. **kernel-initrd**: Generic kernel + initrd boot (NKE, BCM scout, etc.)
5. **kernel-only**: Boot kernel/EFI without initrd (ESXi, etc.)
6. **DGX OS**: DGX OS autoinstall
7. **openshift-coreos**: OpenShift/Assisted Installer - CoreOS live boot
8. **chain-efi**: Chain to arbitrary EFI binary (firmware update, custom loader)
9. **loader-rootfs**: Chain loader.efi with newrootfs
10. **ipxe-shell**: Drop into iPXE shell for debugging
11. **discovery-scout-***: Discovery Scout for x86_64, aarch64, aarch64-dpu
12. **error-instructions**, **exit-instructions**, **unknown-host**: System state templates
13. **whoami**, **carbide-menu-static-ipxe**: Diagnostic/menu templates

## Adding New Templates

To add a new template:

1. Edit `templates.yaml` and add a new entry under `templates:`
2. Rebuild the `carbide-ipxe-renderer` crate
3. The template will be automatically available through the API

Example:

```yaml
  - name: my-custom-os
    description: Custom OS installer
    required_params:
      - kernel_url
      - rootfs_url
    reserved_params:
      - base_url
      - console
    template: |
      #!ipxe
      kernel {{kernel_url}} console={{console}}
      initrd {{rootfs_url}}
      boot
```

## Implementation Details

The templates are loaded at compile time using:
- `include_str!("../templates.yaml")` - Embeds the YAML as a string constant
- `serde_yaml::from_str()` - Parses the YAML during `DefaultIpxeOsRenderer::new()`
- If the YAML is invalid, compilation will fail with a clear error message

This approach ensures:
- **Zero runtime overhead**: Templates are parsed once at compile time
- **Type safety**: YAML structure is validated by serde
- **Easy maintenance**: Templates can be edited without touching Rust code
- **Version control**: Templates are tracked alongside code changes
