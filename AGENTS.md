# AGENTS.md

This file provides guidance for AI coding agents working in the
`ncx-infra-controller-core` repository.

## Project Overview

**NCX Infra Controller (NICo)** is an API-based microservice written in Rust
that provides site-local, zero-trust, bare-metal lifecycle management with
DPU-enforced isolation. It automates the complexity of the bare-metal lifecycle
to fast-track building next-generation AI Cloud offerings.

> **Status:** Experimental/Preview. APIs, configurations, and features may
> change without notice between releases.

### Key Responsibilities

- Hardware inventory management and orchestration
- Redfish-based hardware management
- Hardware testing and firmware updates
- IP address allocation and DNS services
- Power control (on/off/reset)
- Provisioning, wiping, and node-release orchestration
- Machine trust enforcement during tenant switching

## Repository Structure

```
ncx-infra-controller-core/
├── crates/              # Rust crate implementations. To discover all crates
│                        # and their purpose, run `ls crates/` or see the
│                        # [workspace] members list in `Cargo.toml` — each
│                        # crate's own `Cargo.toml` has a `description` field.
│                        # Note: the directory name does NOT always equal the
│                        # crate name (e.g. crates/api/ → crate carbide-api).
│                        # Use `grep '^name =' crates/<dir>/Cargo.toml | head -1`
│                        # to get the actual crate name before running
│                        # `cargo test -p <name>` or similar.
├── book/                # mdBook documentation
├── deploy/              # Kubernetes deployment configs and Kustomization overlays
├── dev/                 # Local dev tools (Dockerfiles, test configs, certs)
├── helm/                # Helm chart for Kubernetes deployment
├── bluefield/           # BlueField DPU-specific components
├── pxe/                 # PXE boot artifact generation
├── lints/               # Custom Clippy lints (carbide-lints crate)
├── include/             # Shared Makefile fragments
├── .github/             # GitHub Actions workflows and templates
├── Cargo.toml           # Workspace dependency management
├── Makefile.toml        # Primary build/task automation
├── Makefile-build.toml  # Build-specific tasks
└── Makefile-package.toml # Packaging tasks
```

## Technology Stack

- **Language:** Rust (edition 2024, toolchain pinned in `rust-toolchain.toml`)
- **Async runtime:** Tokio
- **gRPC framework:** Tonic (with TLS via Rustls/aws_lc_rs)
- **HTTP framework:** Axum (pinned; see `Cargo.toml` for compatibility rationale)
- **Database:** SQLx (compile-time checked queries)
- **Observability:** OpenTelemetry, Tracing (structured logfmt logging)
- **Build tool:** `cargo-make` (TOML task runner)
- **API definitions:** Protocol Buffers (protobuf)

## Build, Test, and Lint Commands

All task automation uses `cargo-make`. Install it with:

```bash
cargo install cargo-make
```

### Building

```bash
# Standard debug build (all workspace crates)
cargo build

# Release build
cargo build --release

# Full CI build + test (mirrors what CI runs)
cargo make build-and-test-release-container-services

# Build the admin CLI locally
cargo make build-cli
```

### Testing

```bash
# Run all tests
cargo test

# Build prerequisites first, then test (recommended for integration tests)
cargo make correctly-execute-tests
```

### Linting and Formatting

```bash
# Run all pre-commit checks (what CI runs)
cargo make pre-commit-verify-workspace

# Individual checks:
cargo make clippy              # Clippy linter (warnings = errors)
cargo make carbide-lints       # Custom carbide lints (requires nightly setup)
cargo make check-format-flow   # Check rustfmt formatting
cargo make check-format-nightly # Check import grouping/sorting (requires nightly)
cargo make check-workspace-deps # Validate dependency declarations in Cargo.toml
cargo make check-licenses      # Validate no restricted licenses introduced
cargo make check-bans          # Check for banned dependencies

# Auto-fix formatting:
cargo fmt --all
cargo make format-nightly      # Also sort imports
```

> **Note:** The nightly toolchain is used only for `check-format-nightly` and
> `carbide-lints`. The stable toolchain pinned in `rust-toolchain.toml` is used
> for everything else.

### Docker Image Builds

All `docker build` commands use `.` (repo root) as the build context.

**SA vs non-SA:** Two x86_64 release Dockerfiles exist:
- `Dockerfile.release-container-sa-x86_64` ("SA" = standalone) — runs clippy,
  lints, format checks, and `build-release`. No tests. Used for local development.
- `Dockerfile.release-container-x86_64` — runs the full build + test suite. The CI path.

Cold builds take ~20–25 minutes on a high-end server. Run in a tmux session to
survive VPN drops or terminal disconnects:

```bash
tmux new-session -d -s nico-build 'docker build ... 2>&1 | tee /tmp/nico-build.log'
tmux attach -t nico-build
```

#### x86_64

```bash
# Prerequisites (build in parallel — each takes ~5–10 min)
docker build -f dev/docker/Dockerfile.build-container-x86_64 -t nico-buildcontainer-x86_64 .
docker build -f dev/docker/Dockerfile.runtime-container-x86_64 -t nico-runtime-container-x86_64 .

# NICo core (SA — lint+build, no tests; ~20–25 min cold)
tmux new-session -d -s nico-build 'docker build \
  --build-arg CONTAINER_BUILD_X86_64=nico-buildcontainer-x86_64 \
  --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 \
  -f dev/docker/Dockerfile.release-container-sa-x86_64 -t nico . 2>&1 | tee /tmp/nico-build.log'

# Standalone admin CLI image
docker build --build-arg CONTAINER_BUILD=nico-buildcontainer-x86_64 -t forge-cli \
  -f dev/docker/Dockerfile.release-forge-cli .

# Machine validation images (depend on runtime container)
docker build --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 \
  -t machine-validation-runner -f dev/docker/Dockerfile.machine-validation-runner .
docker save --output crates/machine-validation/images/machine-validation-runner.tar \
  machine-validation-runner:latest
```

#### aarch64

```bash
docker build -f dev/docker/Dockerfile.build-container-aarch64 -t nico-buildcontainer-aarch64 .
docker build -f dev/docker/Dockerfile.runtime-container-aarch64 -t nico-runtime-container-aarch64 .

tmux new-session -d -s nico-build-aarch64 'docker build \
  --build-arg CONTAINER_BUILD_AARCH64=nico-buildcontainer-aarch64 \
  --build-arg CONTAINER_RUNTIME_AARCH64=nico-runtime-container-aarch64 \
  -f dev/docker/Dockerfile.release-container-aarch64 -t nico-aarch64 . 2>&1 | tee /tmp/nico-build-aarch64.log'
```

### PXE Boot Artifacts

```bash
# One-time: build the PXE build container
cargo make build-pxe-build-container

# Build PXE artifacts inside a privileged container
cargo make pxe-docker-x86

# CI / native path (deps must be pre-installed)
cargo make pxe-native-x86
```

See `book/src/bootable_artifacts.md` for full documentation.

### Basic Testing

After building `nico`, verify all binaries start correctly:

```bash
for bin in carbide carbide-admin-cli carbide-api carbide-dns carbide-dsx-exchange-consumer \
           forge-dhcp-server forge-dpu-agent forge-hw-health forge-log-parser ssh-console; do
  echo "$bin: $(docker run --rm nico /opt/carbide/$bin --help 2>&1 | head -1)"
done
```

Any `exec format error` or missing binary is a red flag.

## Coding Conventions

See [`STYLE_GUIDE.md`](STYLE_GUIDE.md) for detailed Rust coding conventions.
Make sure to review it to ensure changes meet the expected style of the codebase.

## Further Reading

- [`README.md`](README.md) — Project overview and getting started
- [`STYLE_GUIDE.md`](STYLE_GUIDE.md) — Detailed Rust coding conventions
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Contribution workflow and DCO process
- [`book/src/README.md`](book/src/README.md) — Architecture and operational guides
