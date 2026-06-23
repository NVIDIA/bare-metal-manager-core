# AGENTS.md

This file provides guidance for AI coding agents working in the
`infra-controller` repository.

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
infra-controller/
├── crates/              # Rust crate implementations. To discover all crates
│                        # and their purpose, run `ls crates/` or see the
│                        # [workspace] members list in `Cargo.toml` — each
│                        # crate's own `Cargo.toml` has a `description` field.
│                        # Note: the directory name does NOT always equal the
│                        # crate name (e.g. crates/api/ → crate nico-api).
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

When writing tests, prefer the **table-driven** style — see the [Testing section in `STYLE_GUIDE.md`](STYLE_GUIDE.md#testing).
Enumerating a function's input variants as grouped `carbide-test-support` scenarios (`scenarios!` / `value_scenarios!`)
or explicit cases (`check_cases` / `check_values`) is the easiest way to reach thorough coverage of parsers, validators,
conversions, and the like.

### Linting and Formatting

```bash
# Run all pre-commit checks (what CI runs)
cargo make pre-commit-verify-workspace

# Individual checks:
cargo make clippy              # Clippy linter (warnings = errors)
cargo make carbide-lints       # Custom lints (requires nightly setup)
cargo make check-format-nightly # Check rustfmt formatting
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

### Top-level Makefile (rest-api entrypoint)

A top-level [`Makefile`](Makefile) at the repo root provides a thin
discoverable entrypoint for the `rest-api/` Go services. It just
delegates to `rest-api/Makefile`.

```bash
make help                # default goal: list rest-* targets
make rest-build          # build rest-api Go binaries
make rest-test           # run rest-api unit tests
make rest-lint           # lint rest-api
make rest-fmt            # go fmt check on rest-api
make rest-helm-lint      # helm lint rest charts
make rest-docker-build-local
make rest-kind-reset     # spin up the local kind dev cluster (~10 min)
make rest-api/<target>   # pass any target through to rest-api/Makefile
```

Core (Rust) tasks are not in this Makefile; use cargo and `cargo make`
directly as documented above.

## Coding Conventions

Follow the shared [Engineering Guidelines](CONTRIBUTING.md#engineering-guidelines)
for scope control, reuse-before-new-code, evidence-backed assumptions, and
verification expectations.

See [`STYLE_GUIDE.md`](STYLE_GUIDE.md) for detailed Rust coding conventions.
Make sure to review it to ensure changes meet the expected style of the codebase.

## Further Reading

- [`README.md`](README.md) — Project overview and getting started
- [`STYLE_GUIDE.md`](STYLE_GUIDE.md) — Detailed Rust coding conventions
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Contribution workflow and DCO process
- [`book/src/README.md`](book/src/README.md) — Architecture and operational guides
