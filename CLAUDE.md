# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**NCX Infra Controller** (NICo) — zero-touch, bare-metal lifecycle automation for AI datacenter infrastructure. Manages DPU-enforced isolation, out-of-band hardware management, and zero-trust provisioning with no OS requirements on managed hosts.

## Build Commands

This repo uses `cargo-make` (Makefile.toml) for task orchestration. Key commands:

```bash
# Builds
cargo make build-release                          # Release build (all features)
cargo make cargo-docker -- build -p <crate> --release   # Build inside Docker (needed on macOS)

# Tests
cargo make test-flow                              # All workspace tests
cargo make test-docker-postgres-smoke             # Quick Postgres connectivity check
cargo make correctly-execute-tests               # Build prerequisites then run tests

# Lint / Format
cargo make clippy-flow                            # Clippy (requires PostgreSQL running)
cargo make check-format-flow                      # Formatting checks
cargo make check-format-nightly                   # Nightly rustfmt with import sorting
cargo make carbide-lints                          # Custom lints (lints/carbide-lints)
cargo make pre-commit-verify                      # Full pre-commit verification suite
cargo make check-workspace-deps                   # Validate centralized dependency management
cargo make check-licenses                         # License compliance via cargo-deny
```

**Important**: SQLx validates SQL queries at compile time against a live PostgreSQL instance. Set `DATABASE_URL` before compiling. On macOS use `host.docker.internal` as the host.

### PXE Boot Artifacts

```bash
# One-time: build the PXE build container (Ubuntu 24.04 + Rust + mkosi deps)
cargo make build-pxe-build-container

# Build PXE artifacts inside a privileged container (host stays clean)
cargo make pxe-docker-x86

# CI / native path (deps must be pre-installed)
cargo make pxe-native-x86
```

See `book/src/bootable_artifacts.md` for full documentation.

### Docker Image Build Sequence

All `docker build` commands use `.` (repo root) as the build context — some Dockerfiles `COPY` files from `dev/docker/` using repo-relative paths.

**Image naming:** The names below are local development shorthands. CI pulls pre-built images from `nvcr.io/0837451325059433/carbide-dev/` with versioned tags — see `.github/workflows/ci.yaml` for the authoritative names and versions used in CI.

**SA vs non-SA:** Two x86_64 release Dockerfiles exist:
- `Dockerfile.release-container-sa-x86_64` ("SA" = standalone) — runs clippy, lints, format checks, and `build-release`. **No tests.** Used for release builds and local development.
- `Dockerfile.release-container-x86_64` — runs `build-and-test-release-container-services` (build + full test suite). The CI path.

**Build time:** The NICo core image is a cold build of 64 workspace crates plus all dependencies. Budget **~20–25 minutes** on a high-end server (72-core, observed). Run it in a tmux session so it survives VPN drops or terminal disconnects:
```bash
tmux new-session -d -s nico-build 'docker build ... 2>&1 | tee /tmp/nico-build.log'
tmux attach -t nico-build   # to watch progress
```

#### x86_64 Images

```bash
# Prerequisites — build in parallel (build-container takes ~10 min, runtime ~5 min)
docker build -f dev/docker/Dockerfile.build-container-x86_64 -t nico-buildcontainer-x86_64 .
docker build -f dev/docker/Dockerfile.runtime-container-x86_64 -t nico-runtime-container-x86_64 .

# PXE boot artifact sidecar — depends on PXE artifacts (cargo make pxe-docker-x86 first)
# This is a Kubernetes sidecar container that serves PXE blobs; entrypoint sleeps forever.
docker build --build-arg CONTAINER_RUNTIME_X86_64=alpine:latest -t boot-artifacts-x86_64 -f dev/docker/Dockerfile.release-artifacts-x86_64 .

# Machine validation images — depend on runtime container
docker build --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 -t machine-validation-runner -f dev/docker/Dockerfile.machine-validation-runner .
docker save --output crates/machine-validation/images/machine-validation-runner.tar machine-validation-runner:latest
docker build --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 -t machine-validation-config -f dev/docker/Dockerfile.machine-validation-config .

# NICo core (SA — lint+build, no tests; ~20–25 min cold) — depends on build + runtime containers
tmux new-session -d -s nico-build 'docker build \
  --build-arg CONTAINER_BUILD_X86_64=nico-buildcontainer-x86_64 \
  --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 \
  -f dev/docker/Dockerfile.release-container-sa-x86_64 -t nico . 2>&1 | tee /tmp/nico-build.log'

# Standalone carbide-admin-cli image (thin debian:12-slim container, no full stack needed)
docker build --build-arg CONTAINER_BUILD=nico-buildcontainer-x86_64 -t forge-cli -f dev/docker/Dockerfile.release-forge-cli .
```

#### aarch64 Images

aarch64 images target Bluefield DPUs. Build these on an aarch64 host or via cross-compilation.

```bash
# Prerequisites
docker build -f dev/docker/Dockerfile.build-container-aarch64 -t nico-buildcontainer-aarch64 .
docker build -f dev/docker/Dockerfile.runtime-container-aarch64 -t nico-runtime-container-aarch64 .

# PXE/BFB boot artifact sidecar — depends on PXE artifacts (cargo make pxe-docker-aarch64 first)
docker build --build-arg CONTAINER_RUNTIME_AARCH64=alpine:latest -t boot-artifacts-aarch64 -f dev/docker/Dockerfile.release-artifacts-aarch64 .

# NICo core for aarch64 (build + full test suite)
tmux new-session -d -s nico-build-aarch64 'docker build \
  --build-arg CONTAINER_BUILD_AARCH64=nico-buildcontainer-aarch64 \
  --build-arg CONTAINER_RUNTIME_AARCH64=nico-runtime-container-aarch64 \
  -f dev/docker/Dockerfile.release-container-aarch64 -t nico-aarch64 . 2>&1 | tee /tmp/nico-build-aarch64.log'
```

#### Registry Push

Tag and push the 4 runtime images:

```bash
REGISTRY=<your-registry>/carbide
TAG=<version>
docker tag nico                    $REGISTRY/nvmetal-carbide:$TAG
docker tag boot-artifacts-x86_64   $REGISTRY/boot-artifacts-x86_64:$TAG
docker tag boot-artifacts-aarch64  $REGISTRY/boot-artifacts-aarch64:$TAG
docker tag machine-validation-config $REGISTRY/machine-validation-config:$TAG
for img in nvmetal-carbide boot-artifacts-x86_64 boot-artifacts-aarch64 machine-validation-config; do
  docker push $REGISTRY/$img:$TAG
done
```

### Basic Testing the NICo Image

After building `nico`, verify all binaries start correctly:

```bash
for bin in carbide carbide-admin-cli carbide-api carbide-dns carbide-dsx-exchange-consumer \
           forge-dhcp-server forge-dpu-agent forge-hw-health forge-log-parser ssh-console; do
  echo "$bin: $(docker run --rm nico /opt/carbide/$bin --help 2>&1 | head -1)"
done
```

Expected: each line prints a usage string or startup log. Any `exec format error` or missing binary is a red flag.

## Architecture

### Control Plane Services
- `crates/api/` — `carbide-api`, the main gRPC server and control plane
- `crates/agent/` — `carbide-agent`, runs on each Bluefield DPU; connects to the API via gRPC
- `crates/api-db/` — database layer (SQLx, migrations in `api-db/migrations/`)
- `crates/api-model/` — shared data models
- `crates/rpc/` — gRPC/Protobuf definitions; main API surface in `proto/forge.proto`
- `crates/admin-cli/` — `carbide-admin-cli`, operator CLI

### Peripheral Services
`carbide-dhcp`, `carbide-dns`, `carbide-pxe`, `carbide-health`, `carbide-ssh-console`, `carbide-scout` — each lives in its own crate. All communicate with the API over gRPC.

### State Machine
The core of the controller is a file-based state machine in `crates/api/src/state_controller/`:
- `machine/handler.rs` (≈10k lines) drives all machine state transitions
- Key types: `Machine`, `MachineState`, `Instance`, `InstanceState`
- Next-state resolvers: `MachineNextStateResolver`, `InstanceNextStateResolver`
- State changes are committed in database transactions via SQLx

### gRPC Pattern
All inter-service communication uses gRPC + Protobuf via `tonic`. Proto files live in `crates/rpc/proto/`. Services include Forge (main), DNS, Health, MeasuredBoot, SiteExplorer.

### Database
PostgreSQL via SQLx (compile-time verified queries). Pools and transactions managed through `sqlx::PgPool`. Schema migrations in `crates/api-db/migrations/`.

### Config & Secrets
- TOML config via `figment` (supports env overrides)
- Secrets via `forge-secrets` crate; Vault integration; SPIFFE certs at `/var/run/secrets/spiffe.io/`
- Redfish API credentials for BMC access

### Observability
- Structured logging with `tracing`
- OpenTelemetry + Prometheus metrics
- Custom metrics emitter in `crates/api/`

### Custom Lints
Project-specific lints in `lints/carbide-lints/` compiled with nightly Rust (`nightly-2025-11-14`).

## Testing

Integration tests are in `crates/api-integration-tests/` and `crates/api-test-helper/`. Test fixtures live in `tests/common/`. Unit tests are embedded with `#[cfg(test)]` inside crates.

To run a single test:
```bash
cargo test -p <crate-name> <test_name>
```

Database tests spin up Docker Postgres. On macOS, use `host.docker.internal` in `DATABASE_URL`.

## Contributing Requirements

- All commits require a [DCO](https://developercertificate.org/) sign-off: `git commit -s`
- PRs should be single-purpose; all CI checks must pass before review
- Rust edition 2024; Apache 2.0 license
- Workspace dependencies managed centrally in the root `Cargo.toml` — do not add crate-level version pins unless there's an explicit reason
