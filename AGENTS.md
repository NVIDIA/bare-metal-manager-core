# AGENTS.md

This file provides guidance for AI coding agents working in the
`infra-controller` repository.

## Project Overview

**NVIDIA Infra Controller (NICo)** is an API-based microservice written in Rust
and Golang that provides site-local, zero-trust, bare-metal lifecycle
management with DPU-enforced isolation. It automates the complexity of the
bare-metal lifecycle to fast-track building next-generation AI Cloud offerings.

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
├── rest-api/            # Golang-based REST API
├── Cargo.toml           # Workspace dependency management
├── Makefile.toml        # Primary build/task automation
├── Makefile-build.toml  # Build-specific tasks
└── Makefile-package.toml # Packaging tasks
```

## Technology Stack

### gRPC API and components:
- **Language:** Rust (edition 2024, toolchain pinned in `rust-toolchain.toml`)
- **Async runtime:** Tokio
- **gRPC framework:** Tonic (with TLS via Rustls/aws_lc_rs)
- **HTTP framework:** Axum (pinned; see `Cargo.toml` for compatibility rationale)
- **Database:** SQLx (compile-time checked queries)
- **Observability:** OpenTelemetry, Tracing (structured logfmt logging)
- **Build tool:** `cargo-make` (TOML task runner)
- **API definitions:** Protocol Buffers (protobuf)

### REST API and components
- **Language (REST API):** Golang 1.26.x

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

Keep test rack-profile capability counts aligned with the inventory the fixture
actually instantiates. Use zero for unsupported component types so tests do not
generate expected-but-absent discovery errors.

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

# Optional maintenance check (not part of required CI or pre-commit):
cargo make check-isolated-package-builds # Check each package with default features

# Auto-fix formatting:
cargo fmt --all
cargo make format-nightly      # Also sort imports
```

> **Note:** The nightly toolchain is used only for `check-format-nightly` and
> `carbide-lints`. The stable toolchain pinned in `rust-toolchain.toml` is used
> for everything else.

### Top-level Makefile entrypoints

A top-level [`Makefile`](Makefile) at the repo root provides a thin
discoverable entrypoint for selected Core workflows and the `rest-api/` Go
services. It delegates to cargo-make or `rest-api/Makefile`.

```bash
make help                # default goal: list available targets
make core/check-isolated-package-builds # optional independent default-feature builds
make rest-build          # build rest-api Go binaries
make rest-test           # run rest-api unit tests
make rest-lint           # lint rest-api
make rest-fmt            # go fmt check on rest-api
make rest-helm-lint      # helm lint rest charts
make rest-docker-build-local
make rest-kind-reset     # spin up the local kind dev cluster (~10 min)
make rest-api/<target>   # pass any target through to rest-api/Makefile
```

Published container artifacts must pin external base images by immutable
digest. When architecture-specific targets share a base image, define one
overridable variable so their versions cannot drift independently.

## Coding Conventions

Follow the shared [Engineering Guidelines](CONTRIBUTING.md#engineering-guidelines)
for scope control, reuse-before-new-code, evidence-backed assumptions, and
verification expectations.

See [`STYLE_GUIDE.md`](STYLE_GUIDE.md) for detailed Rust coding conventions.
Make sure to review it to ensure changes meet the expected style of the codebase.

### Instrumentation: logs and metrics

The decision rule:

- **Just logging words?** Use plain `tracing::` macros with structured fields
  (`warn!(%machine_id, error = %e, "...")`). Most log sites are and stay this.
- **Does the event deserve a count, rate, or duration** (a failure you'd alert
  on, an outcome you'd trend, a hot-path rate)? Declare it once as a
  `carbide_instrument::Event` and `emit()` it — that produces the metric and
  (optionally) the log line together, correlated by `span_id`:

  ```rust
  #[derive(carbide_instrument::Event)]
  #[event(name = "carbide_power_control_total", component = "component_manager",
          log = warn, metric = counter, message = "power control failed")]
  struct PowerControlFailed {
      #[label]   backend: Backend,  // bounded via LabelValue — enums, usually
      #[context] error: String,     // high-cardinality — log line only
  }
  ```

  `log = off, metric = counter` counts a hot-path event with no log line at
  all; `metric = none` is a typed log. Never put `machine_id`/IPs/error text
  in a `#[label]` — that's what `#[context]` is for, and `String` doesn't
  implement `LabelValue` precisely to stop it. A bounded-but-not-enum value
  (a vendor, a SKU) can get a manual `LabelValue` impl on a newtype — the
  reviewed escape hatch — but only when the value is bounded *at the call
  site*; anything caller-supplied stays in `#[context]`.
- **Point-in-time state** ("how many machines are in state X") stays on the
  existing observable-gauge / `SharedMetricsHolder` pattern — the framework models
  occurrences, not state.

New metric names are validated at compile time (`carbide_` prefix, `_total`
counters, unit-suffixed histograms) and the name in the attribute is the
exposed name, verbatim. Existing metric names never change. The full standard
lives in [`docs/observability/instrumentation.md`](docs/observability/instrumentation.md).

## Further Reading

- [`README.md`](README.md) — Project overview and getting started
- [`STYLE_GUIDE.md`](STYLE_GUIDE.md) — Detailed Rust coding conventions
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Contribution workflow and DCO process
- [`book/src/README.md`](book/src/README.md) — Architecture and operational guides
