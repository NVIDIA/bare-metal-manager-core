# Guide: Building PXE Boot Artifacts

This guide describes the two paths for building x86_64 PXE boot artifacts: a Docker-based path for local development (keeps the host clean) and a native path for CI runners.

---

## What's in place

| Item | Location | Purpose |
|------|----------|---------|
| **Makefile task: `pxe-docker-x86`** | `Makefile.toml` | Build x86_64 PXE artifacts inside a privileged container. Host stays clean. Requires `build-pxe-build-container` once. |
| **Makefile task: `build-pxe-build-container`** | `Makefile.toml` | Build the local PXE build container image (`carbide-pxe-builder`: Ubuntu 24.04 + Rust 1.90 + mkosi deps). Required once before `pxe-docker-x86`. |
| **Makefile task: `pxe-native-x86`** | `Makefile.toml` | Build x86_64 PXE artifacts natively on the host/runner. Deps must be pre-installed. Used in CI. |
| **PXE build Dockerfile** | `dev/docker/Dockerfile.pxe-build-container` | Defines `carbide-pxe-builder`: Ubuntu 24.04 with Rust 1.90, cargo-make, mkosi host tools, iPXE build deps, scout Rust deps. Distinct from the general-purpose `carbide-build-x86_64` build container. |
| **CI action: `setup-mkosi-environment`** | `.github/actions/setup-mkosi-environment/` | Installs all PXE build deps on a GHA runner for the native path. |
| **PXE Makefile** | `pxe/Makefile.toml` | Underlying build tasks (`build-boot-artifacts-x86-host-sa`, mkosi, iPXE, apt repo). |

All commands below are run from the **repository root** unless noted.

---

## What gets built

The x86_64 PXE artifact build produces:

| Artifact | Path |
|----------|------|
| iPXE EFI kernel | `pxe/static/blobs/internal/x86_64/ipxe.efi` |
| iPXE Golan EFI | `pxe/static/blobs/internal/x86_64/golan.efi` |
| Scout OS image (cpio) | `pxe/static/blobs/internal/x86_64/scout.cpio.zst` |
| Scout EFI loader | `pxe/static/blobs/internal/x86_64/scout.efi` |
| QCOW imager EFI | `pxe/static/blobs/internal/x86_64/qcow-imager.efi` |
| Scout apt repo | `pxe/static/blobs/internal/apt/` |
| forge-scout deb | `target/debs/forge-scout_*_amd64.deb` |

---

## Submodules

Both paths require the git submodules to be present. Initialize them once:

```bash
git submodule update --init
```

This checks out:
- `pxe/mkosi` — the mkosi OS image builder (used directly by the PXE Makefile)
- `pxe/ipxe/upstream` — iPXE source

---

## Path 1: Docker (local development)

Use this on your workstation. All build dependencies are isolated inside a container image; nothing is installed on the host beyond Docker and `cargo-make`.


### Why `--privileged`?

The mkosi step builds a bootable OS image using Linux user namespaces for sandboxing. This requires elevated privileges that a standard container doesn't have. `--privileged` disables AppArmor restrictions for the container, allowing mkosi's namespace operations to work. The build output is written back to your repo via the mount — the host filesystem is not otherwise affected.

### Prerequisites

1. **Docker** — installed and running.

2. **cargo-make** — needed to invoke the Makefile tasks:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source $HOME/.cargo/env
   cargo install cargo-make --locked
   ```

### Quick start

```bash
# One-time: initialize submodules
git submodule update --init

# One-time: build the container image (~10-15 min)
cargo make build-pxe-build-container

# Build PXE artifacts (~30-60 min depending on network)
cargo make pxe-docker-x86
```

Artifacts appear in `pxe/static/blobs/internal/x86_64/` and `target/debs/` in your working tree.

### Repeat builds

The `pxe-docker-x86` task mounts `~/.sccache` into the container for Rust build caching. The Rust compilation step (`forge-scout`) is much faster on subsequent runs. The mkosi step re-downloads Ubuntu packages on every run unless you modify the mkosi profile to use a local mirror.

You do **not** need to rebuild the container image (`build-pxe-build-container`) unless the Dockerfile changes.

---

## Path 2: Native (CI runners)

Use this in GitHub Actions or on any host where you're willing to install deps directly.

### Prerequisites

All deps must be installed before running. In CI, use the provided composite action:

```yaml
- uses: ./.github/actions/setup-mkosi-environment
  with:
    rust-version: '1.90.0'
    arch: x86_64
```

This action installs system packages (mkosi ecosystem, iPXE deps, Rust binary deps), Rust 1.90.0, cargo-make, sccache, and sets the required AppArmor sysctls:
```
kernel.apparmor_restrict_unprivileged_userns=0
kernel.apparmor_restrict_unprivileged_unconfined=0
```

### Running the build

```bash
cargo make pxe-native-x86
```

Or directly:

```bash
cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-x86-host-sa
```

### Example CI job

```yaml
- name: Checkout
  uses: actions/checkout@v4
  with:
    submodules: recursive

- name: Setup mkosi environment
  uses: ./.github/actions/setup-mkosi-environment
  with:
    rust-version: '1.90.0'
    arch: x86_64

- name: Build PXE artifacts
  run: cargo make pxe-native-x86
```

---

## Why the build is split from the Docker images

The NICo container images (`nico`, `boot-artifacts-x86_64`) are built with `docker build` and don't require these host-side tools. The PXE artifact build is kept separate because:

- **mkosi** bootstraps a real OS image using Linux user namespaces, which cannot run inside a standard (unprivileged) Docker layer
- **iPXE** is compiled from C source with a custom `ld.bfd` invocation that conflicts with the `lld`-defaulting build container

The Dockerfile release pipeline (`image-build.md`) treats the PXE artifacts as a prerequisite that feeds into the final `boot-artifacts-x86_64` Docker image.

---

## Troubleshooting

**`mkosi` fails with namespace errors**

Docker path: ensure the container is run with `--privileged` (the `pxe-docker-x86` task does this automatically).

Native path: verify the AppArmor sysctls were applied:
```bash
sysctl kernel.apparmor_restrict_unprivileged_userns
# should be 0
```

**iPXE build fails with linker errors**

The iPXE build requires GNU `ld` (`ld.bfd`), not LLVM `lld`. The `SA_ENABLEMENT=1` environment variable (set by both tasks) tells the iPXE Makefile to pass `LD=/usr/bin/ld.bfd` explicitly.

**What is `SA_ENABLEMENT`?**

`SA_ENABLEMENT` (Standalone) gates out build steps that are only relevant when building with internal NVIDIA infrastructure. Both `pxe-docker-x86` and `pxe-native-x86` set it automatically. The underlying task names with the `-sa` suffix (e.g. `build-boot-artifacts-x86-host-sa`) reflect the same distinction.

**`pxe/mkosi/bin/mkosi` not found**

Submodules are not initialized. Run:
```bash
git submodule update --init
```

**File ownership errors after Docker build**

The `pxe-docker-x86` task runs the container as root and chowns `/code` back to your user at the end. If a previous run was interrupted, run:
```bash
cargo make fix-target-permissions
```

**mkosi downloads packages slowly**

mkosi uses `--with-network` to pull Ubuntu Noble packages from public mirrors during the build. Build time varies with network speed. There is no offline mode without a local mirror configured in the mkosi profiles.
