# mlxconfig-firmware

Firmware management for Mellanox NICs (BlueField-3 SuperNIC and ConnectX-7), including flash, verify, and reset operations. Supports sourcing firmware from local files, HTTPS URLs, and SSH/SCP, with optional authentication.

## Overview

The firmware lifecycle for Mellanox NICs follows this sequence:

1. **Flash** -- burn new firmware onto the device via `flint`
2. **Verify version** -- confirm the expected firmware version is staged (works pre-reset)
3. **Reset** -- activate the new firmware via `mlxfwreset`
4. **Verify image** -- compare the running firmware against a known-good image (works post-reset)

For debug firmware builds, a device configuration (e.g., a debug token) must be applied via `mlxconfig apply` before the firmware can be burned. The crate handles this automatically when a device config source is configured.

### Underlying tools

The crate orchestrates several Mellanox CLI tools:

| Tool | Purpose | Crate |
|---|---|---|
| `flint` | Burn firmware, verify against image | mlxconfig-lockdown |
| `mlxconfig` | Apply device config, reset NV config | mlxconfig-runner |
| `mlxfwreset` | Device reset to activate firmware | mlxconfig-firmware (reset module) |
| `mlxfwmanager` | Query installed firmware version | mlxconfig-device |

## Architecture

```
mlxconfig-firmware/src/
  lib.rs          -- Module declarations
  error.rs        -- FirmwareError enum and FirmwareResult type alias
  credentials.rs  -- Unified Credentials enum (HTTP + SSH)
  source.rs       -- FirmwareSource enum (Local, Http, Ssh) with from_url() parser
  config.rs       -- TOML-based SupernicFirmwareConfig
  flasher.rs      -- FirmwareFlasher orchestrator and FlashResult
  reset.rs        -- MlxFwResetRunner (wraps mlxfwreset CLI)
```

## Firmware Sources

`FirmwareSource` is an enum with three variants representing where firmware binaries come from. All sources resolve to a local file path, downloading if necessary.

### URL Parsing

The recommended way to create a `FirmwareSource` is via `from_url()`, which detects the source type from the URL prefix:

| Prefix | Source type | Example |
|---|---|---|
| `https://` or `http://` | Http | `https://artifacts.example.com/fw/prod.bin` |
| `ssh://` | Ssh (SCP-style) | `ssh://deploy@host:path/to/firmware.bin` |
| `file://` | Local | `file:///opt/firmware/prod.bin` |
| (none) | Local | `/opt/firmware/prod.bin` |

```rust
use mlxconfig_firmware::source::FirmwareSource;

// Local file
let source = FirmwareSource::from_url("/path/to/firmware.signed.bin")?;

// Local file with file:// prefix
let source = FirmwareSource::from_url("file:///opt/firmware/prod.signed.bin")?;

// HTTPS
let source = FirmwareSource::from_url("https://artifacts.example.com/fw/prod.signed.bin")?;

// SSH (SCP-style colon separator: ssh://[user@]host:path)
let source = FirmwareSource::from_url("ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin")?;

// SSH with absolute path
let source = FirmwareSource::from_url("ssh://deploy@build-server.example.com:/opt/fw/prod.signed.bin")?;
```

### Direct Construction

You can also create sources directly:

```rust
use mlxconfig_firmware::source::FirmwareSource;

let local = FirmwareSource::local("/path/to/firmware.signed.bin");
let http = FirmwareSource::http("https://artifacts.example.com/fw/prod.signed.bin");
let ssh = FirmwareSource::ssh("build-server.example.com", "/builds/fw/prod.signed.bin")
    .with_username("deploy")
    .with_port(2222);
```

### SSH URL Format

SSH URLs use SCP-style colon separators: `ssh://[user@]host:path`

- `ssh://host:relative/path` -- relative path from user's home directory
- `ssh://host:/absolute/path` -- absolute path
- `ssh://user@host:path` -- explicit username (defaults to current user)

This format avoids ambiguity between port numbers and paths that arises with standard URL parsing.

**Note on sudo:** When running with `sudo`, the SSH agent socket (`SSH_AUTH_SOCK`) and home directory (`HOME`) are stripped from the environment. Use `sudo -E` to preserve them, or the SSH source won't be able to find your agent or `~/.ssh/known_hosts`.

## Credentials

The `Credentials` enum provides a unified type for both HTTP and SSH authentication. Validation that the credential type matches the source type happens at resolve time.

```rust
use mlxconfig_firmware::credentials::Credentials;

// HTTP credentials
let bearer = Credentials::bearer_token("eyJhbGciOi...");
let basic = Credentials::basic_auth("deploy", "s3cret");
let header = Credentials::header("X-API-Key", "abc123");

// SSH credentials
let key = Credentials::ssh_key("/home/deploy/.ssh/id_ed25519");
let key_pass = Credentials::ssh_key_with_passphrase("/home/deploy/.ssh/id_rsa", "my-passphrase");
let agent = Credentials::ssh_agent();
```

### Applying Credentials to Sources

```rust
use mlxconfig_firmware::source::FirmwareSource;
use mlxconfig_firmware::credentials::Credentials;

// HTTPS with bearer token
let source = FirmwareSource::from_url("https://artifacts.example.com/fw/prod.signed.bin")?
    .with_credentials(Credentials::bearer_token("eyJhbGciOi..."));

// HTTPS with basic auth
let source = FirmwareSource::from_url("https://internal.example.com/fw/prod.signed.bin")?
    .with_credentials(Credentials::basic_auth("deploy", "s3cret"));

// SSH with agent
let source = FirmwareSource::from_url("ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin")?
    .with_credentials(Credentials::ssh_agent());

// SSH with key file
let source = FirmwareSource::from_url("ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin")?
    .with_credentials(Credentials::ssh_key("/home/deploy/.ssh/id_ed25519"));
```

## FirmwareFlasher

`FirmwareFlasher` is the main orchestrator. It uses a builder pattern -- only `device_id` is required. Everything else is optional and depends on the operation you're performing.

### Builder methods

| Method | Description | Required for |
|---|---|---|
| `new(device_id)` | Create a flasher for a PCI device | All operations |
| `with_firmware(source)` | Set the firmware source | `flash()` |
| `with_device_conf(source)` | Set the device config source (e.g., debug token) | Debug firmware only |
| `with_expected_version(ver)` | Set the expected firmware version | `verify_version()` |
| `with_reset_device(dev)` | Set a different device ID for mlxfwreset | `reset()` (optional) |
| `with_reset_level(level)` | Set the mlxfwreset level (default: 3) | `reset()` (optional) |
| `with_work_dir(dir)` | Set staging directory for downloads | Remote sources (optional) |
| `with_dry_run(bool)` | Enable dry-run mode | Any (optional) |
| `with_verbose(bool)` | Enable verbose logging | Any (optional) |

### Operations

| Method | What it does | Async |
|---|---|---|
| `flash()` | Apply device config (if set) + burn firmware via flint | Yes |
| `verify_image(path)` | Compare device firmware against an image file | No |
| `verify_version()` | Check installed version matches expected | No |
| `reset()` | Reset device via mlxfwreset | No |

### Code Examples

#### Flash local firmware (production)

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;
use mlxconfig_firmware::source::FirmwareSource;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_firmware(FirmwareSource::local("/path/to/prod.signed.bin"));

let result = flasher.flash().await?;
```

#### Flash remote firmware with HTTPS

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;
use mlxconfig_firmware::source::FirmwareSource;
use mlxconfig_firmware::credentials::Credentials;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_firmware(
        FirmwareSource::from_url("https://artifacts.example.com/fw/prod.signed.bin")?
            .with_credentials(Credentials::bearer_token("my-token")),
    );

let result = flasher.flash().await?;
```

#### Flash debug firmware with device config

Debug firmware requires a device configuration (e.g., debug token) to be applied before burning. The flasher handles the sequencing automatically:

1. Resolve and apply the device config via `mlxconfig apply`
2. Resolve and burn the firmware via `flint burn`

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;
use mlxconfig_firmware::source::FirmwareSource;
use mlxconfig_firmware::credentials::Credentials;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_firmware(
        FirmwareSource::from_url("https://artifacts.example.com/fw/debug.signed.bin")?
            .with_credentials(Credentials::bearer_token("my-token")),
    )
    .with_device_conf(
        FirmwareSource::from_url("ssh://deploy@build-server.example.com:builds/tokens/debug.conf.bin")?
            .with_credentials(Credentials::ssh_agent()),
    )
    .with_verbose(true);

let result = flasher.flash().await?;
assert!(result.device_conf_applied);
```

#### Full lifecycle: flash, verify, reset, verify image

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;
use mlxconfig_firmware::source::FirmwareSource;

let firmware_path = "/path/to/firmware.signed.bin";

// Flash
let flasher = FirmwareFlasher::new("4b:00.0")
    .with_firmware(FirmwareSource::local(firmware_path))
    .with_expected_version("32.43.1014");

let result = flasher.flash().await?;

// Verify version works before reset
let version = flasher.verify_version()?;

// Reset device to activate
let output = flasher.reset()?;

// Verify image works after reset
let output = flasher.verify_image(firmware_path.as_ref())?;
```

#### Verify version only (no flash)

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_expected_version("32.43.1014");

match flasher.verify_version()? {
    Some(v) => println!("Firmware version OK: {v}"),
    None => println!("No expected version configured"),
}
```

#### Reset only

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_reset_level(3);

flasher.reset()?;
```

#### Dry-run mode

Dry-run logs the commands that would be executed without actually running them.

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;
use mlxconfig_firmware::source::FirmwareSource;

let flasher = FirmwareFlasher::new("4b:00.0")
    .with_firmware(FirmwareSource::local("/path/to/firmware.signed.bin"))
    .with_dry_run(true)
    .with_verbose(true);

// Logs the flint burn command but doesn't execute it.
let result = flasher.flash().await?;
```

#### Load from TOML config file

```rust
use mlxconfig_firmware::flasher::FirmwareFlasher;

let flasher = FirmwareFlasher::from_config_file("4b:00.0", "/etc/carbide/firmware.toml")?;
let result = flasher.flash().await?;
```

## TOML Configuration

`SupernicFirmwareConfig` is a TOML-serializable configuration for firmware management. In the Carbide API config, this lives under the `[supernic_firmware_config]` block. It can also be used standalone with `FirmwareFlasher::from_config_file()`.

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `firmware_url` | string | Yes | Firmware source: local path, `file://`, `https://`, or `ssh://` URL |
| `firmware_credentials` | table | No | Authentication for firmware download |
| `device_conf_url` | string | No | Device config source (same URL formats) |
| `device_conf_credentials` | table | No | Authentication for device config download |
| `expected_version` | string | No | Firmware version to verify after flashing |

### Credential types

The `type` field determines the credential variant:

| Type | Fields | For |
|---|---|---|
| `bearer_token` | `token` | HTTPS sources |
| `basic_auth` | `username`, `password` | HTTPS sources |
| `header` | `name`, `value` | HTTPS sources |
| `ssh_key` | `path`, `passphrase` (optional) | SSH sources |
| `ssh_agent` | (none) | SSH sources |

Using the wrong credential type for a source (e.g., SSH key with HTTPS URL) returns a config error at resolve time.

### TOML Examples

#### Local firmware, no auth

The simplest possible config -- a firmware binary on the local filesystem.

```toml
firmware_url = "/opt/firmware/prod-32.43.1014.signed.bin"
```

#### Local firmware with file:// prefix and version check

```toml
firmware_url = "file:///opt/firmware/prod-32.43.1014.signed.bin"
expected_version = "32.43.1014"
```

#### HTTPS firmware with bearer token

```toml
firmware_url = "https://artifacts.example.com/fw/prod-32.43.1014.signed.bin"
expected_version = "32.43.1014"

[firmware_credentials]
type = "bearer_token"
token = "asjkhdgagkjasdhgaskdjhgaskdj...."
```

#### HTTPS firmware with basic auth

```toml
firmware_url = "https://internal.example.com/fw/prod-32.43.1014.signed.bin"

[firmware_credentials]
type = "basic_auth"
username = "deploy"
password = "s3cret"
```

#### HTTPS firmware with custom header

```toml
firmware_url = "https://artifacts.example.com/fw/prod-32.43.1014.signed.bin"

[firmware_credentials]
type = "header"
name = "X-API-Key"
value = "abc123def456"
```

#### SSH firmware with key file

Note the SCP-style colon separator between host and path.

```toml
firmware_url = "ssh://deploy@build-server.example.com:builds/fw/prod-32.43.1014.signed.bin"

[firmware_credentials]
type = "ssh_key"
path = "/home/deploy/.ssh/id_ed25519"
```

#### SSH firmware with key file and passphrase

```toml
firmware_url = "ssh://deploy@build-server.example.com:builds/fw/prod-32.43.1014.signed.bin"

[firmware_credentials]
type = "ssh_key"
path = "/home/deploy/.ssh/id_rsa"
passphrase = "my-key-passphrase"
```

#### SSH firmware with SSH agent

```toml
firmware_url = "ssh://deploy@build-server.example.com:builds/fw/prod-32.43.1014.signed.bin"

[firmware_credentials]
type = "ssh_agent"
```

#### Debug firmware with device config (full example)

Firmware from HTTPS with a bearer token, device config from SSH with agent auth, and version verification.

```toml
firmware_url = "https://artifacts.example.com/fw/debug-32.43.1014.signed.bin"
expected_version = "32.43.1014"

[firmware_credentials]
type = "bearer_token"
token = "asjkhdgagkjasdhgaskdjhgaskdj...."

device_conf_url = "ssh://deploy@build-server.example.com:builds/configs/debug.conf.bin"

[device_conf_credentials]
type = "ssh_agent"
```

#### Mixed sources: local firmware, remote device config

```toml
firmware_url = "/opt/firmware/debug-32.43.1014.signed.bin"

device_conf_url = "https://configs.example.com/debug.conf.bin"

[device_conf_credentials]
type = "bearer_token"
token = "asjkhdgagkjasdhgaskdjhgaskdj...."
```

## CLI (mlxconfig-embedded)

The `mlxconfig-embedded` binary includes a `firmware` subcommand that exercises all firmware operations. This is a reference/playground CLI -- not a production tool.

### Global firmware flags

These flags apply to all firmware subcommands:

```
firmware [--verbose] [--dry-run] [--work-dir <path>] <subcommand>
```

| Flag | Short | Description |
|---|---|---|
| `--verbose` | `-v` | Enable verbose output |
| `--dry-run` | `-n` | Print commands without executing |
| `--work-dir` | | Staging directory for downloads (default: `/tmp/mlxconfig-firmware`) |

### flash

Flash firmware onto a device. Supports local, HTTPS, and SSH sources.

```bash
# Local firmware
mlxconfig-embedded firmware flash 4b:00.0 /path/to/firmware.signed.bin

# Local firmware with file:// prefix
mlxconfig-embedded firmware flash 4b:00.0 file:///opt/firmware/prod.signed.bin

# HTTPS with bearer token
mlxconfig-embedded firmware flash 4b:00.0 \
    https://artifacts.example.com/fw/prod.signed.bin \
    --firmware-bearer-token "eyJhbGciOi..."

# HTTPS with basic auth
mlxconfig-embedded firmware flash 4b:00.0 \
    https://internal.example.com/fw/prod.signed.bin \
    --firmware-basic-auth "deploy:s3cret"

# SSH with agent (SCP-style URL)
mlxconfig-embedded firmware flash 4b:00.0 \
    ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin \
    --firmware-ssh-agent

# SSH with key file
mlxconfig-embedded firmware flash 4b:00.0 \
    ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin \
    --firmware-ssh-key /home/deploy/.ssh/id_ed25519

# Debug firmware with device config
mlxconfig-embedded firmware flash 4b:00.0 \
    https://artifacts.example.com/fw/debug.signed.bin \
    --firmware-bearer-token "eyJhbGciOi..." \
    --device-conf-url ssh://deploy@build-server.example.com:builds/configs/debug.conf.bin \
    --device-conf-ssh-agent

# Flash with version check
mlxconfig-embedded firmware flash 4b:00.0 /path/to/firmware.signed.bin \
    --expected-version 32.43.1014

# Dry-run
mlxconfig-embedded firmware --dry-run --verbose flash 4b:00.0 /path/to/firmware.signed.bin
```

### flash-config

Flash using a TOML configuration file.

```bash
mlxconfig-embedded firmware flash-config 4b:00.0 /etc/carbide/firmware.toml

# Dry-run
mlxconfig-embedded firmware --dry-run flash-config 4b:00.0 /etc/carbide/firmware.toml
```

### verify-image

Verify the firmware on a device against a known-good image. This uses `flint -d <dev> -i <image> verify`. The device must be reset after flashing before verify-image will work.

Supports the same source types as flash (local, HTTPS, SSH). Remote images are downloaded to the work directory first.

```bash
# Local image
mlxconfig-embedded firmware verify-image 4b:00.0 /path/to/firmware.signed.bin

# SSH with agent
mlxconfig-embedded firmware verify-image 4b:00.0 \
    ssh://deploy@build-server.example.com:builds/fw/prod.signed.bin \
    --ssh-agent

# HTTPS with bearer token
mlxconfig-embedded firmware verify-image 4b:00.0 \
    https://artifacts.example.com/fw/prod.signed.bin \
    --bearer-token "eyJhbGciOi..."

# HTTPS with basic auth
mlxconfig-embedded firmware verify-image 4b:00.0 \
    https://internal.example.com/fw/prod.signed.bin \
    --basic-auth "deploy:s3cret"
```

### verify-version

Check that the installed firmware version matches an expected version. Queries the device via `mlxfwmanager`. Works before or after a device reset.

```bash
mlxconfig-embedded firmware verify-version 4b:00.0 32.43.1014
```

### reset

Reset the device to activate newly flashed firmware. Uses `mlxfwreset`. Default reset level is 3 (full NIC reset).

```bash
# Default level (3)
mlxconfig-embedded firmware reset 4b:00.0

# Custom level
mlxconfig-embedded firmware reset 4b:00.0 --level 5
```

### config-reset

Reset all mlxconfig NV configuration parameters on the device to factory defaults. This is NOT a device reset -- use `reset` for that.

```bash
mlxconfig-embedded firmware config-reset 4b:00.0
```

### Full lifecycle example

```bash
# 1. Flash
sudo mlxconfig-embedded firmware flash 4b:00.0 /path/to/firmware.signed.bin \
    --expected-version 32.43.1014

# 2. Verify version (works pre-reset)
sudo mlxconfig-embedded firmware verify-version 4b:00.0 32.43.1014

# 3. Reset to activate
sudo mlxconfig-embedded firmware reset 4b:00.0

# 4. Verify image (works post-reset)
sudo mlxconfig-embedded firmware verify-image 4b:00.0 /path/to/firmware.signed.bin
```

## MlxConfigApplier

The `MlxConfigApplier` in `mlxconfig-runner` provides two device-level operations used by the firmware crate:

- `apply(config_file)` -- runs `mlxconfig -d <dev> --yes apply <file>` (used for device config)
- `reset_config()` -- runs `mlxconfig -d <dev> --yes reset` (factory reset of NV config)

These are separate from `MlxConfigRunner` because they don't require a variable registry.

## Error Handling

All operations return `FirmwareResult<T>` (alias for `Result<T, FirmwareError>`). Key error variants:

| Variant | When |
|---|---|
| `ConfigError` | Missing firmware source, invalid TOML, wrong credential type |
| `FileNotFound` | Local source file doesn't exist |
| `HttpError` | HTTPS download failed (network, auth, HTTP status) |
| `SshError` | SSH connection or transfer failed |
| `FlintError` | `flint burn` or `flint verify` failed |
| `MlxConfigError` | `mlxconfig apply` or `mlxconfig reset` failed |
| `ResetFailed` | `mlxfwreset` failed |
| `VerificationFailed` | Version mismatch or device query failure |
| `PermissionDenied` | Operation requires root |
| `DeviceNotFound` | PCI device not found |
| `MlxFwResetNotFound` | `mlxfwreset` binary not on the system |

## Known Limitations

- **SSH binary transfer uses base64 encoding.** The `async-ssh2-tokio` library returns command stdout as a UTF-8 `String`, which corrupts binary data. We work around this by running `cat <file> | base64` on the remote host and decoding locally. This means the remote host must have `base64` installed (standard on Linux and macOS).

- **SSH host key verification uses `~/.ssh/known_hosts`.** When running under `sudo`, this resolves to root's known_hosts, not the invoking user's. Use `sudo -E` to preserve the `HOME` and `SSH_AUTH_SOCK` environment variables.

- **All firmware operations require root.** The underlying tools (`flint`, `mlxconfig`, `mlxfwreset`) require root access to interact with NIC hardware.

- **verify-image requires a device reset first.** After flashing, `flint verify` against an image will fail until the device has been reset with `mlxfwreset`. Use `verify-version` for pre-reset validation.
