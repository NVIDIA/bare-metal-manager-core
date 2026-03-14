# Guide: Cargo via Docker on macOS

This guide describes what is in place for running Cargo (build, test, check) via Docker on macOS and how to use it when native Cargo is problematic (e.g. Rust version mismatch, `tss-esapi` or other platform issues).

---

## What’s in place

| Item | Location | Purpose |
|------|----------|--------|
| **Makefile task: `cargo-docker-minimal`** | `Makefile.toml` | Run Cargo in the minimal image (`carbide-build-minimal`: Rust 1.90 + protoc). **Recommended on Mac.** Requires `build-cargo-docker-image-minimal` once. |
| **Makefile task: `build-cargo-docker-image-minimal`** | `Makefile.toml` | Build the minimal image (Rust + protoc only). Quick (~2–5 min). Required once for workspace builds (e.g. `carbide-rpc` needs `protoc`). |
| **Makefile task: `cargo-docker`** | `Makefile.toml` | Run Cargo inside the repo’s full build container (`carbide-build-x86_64`). Requires building that image first. |
| **Makefile task: `build-cargo-docker-image`** | `Makefile.toml` | Build the full Linux build image from `dev/docker/Dockerfile.build-container-x86_64`. Slow on Apple Silicon (45+ min). |
| **This guide** | `docs/development/cargo-via-docker-macos.md` | How to use the above and when to choose which option. |
| **Minimal Dockerfile** | `dev/docker/Dockerfile.cargo-docker-minimal` | Rust 1.90 + `protobuf-compiler` + `libprotobuf-dev` (well-known types). Used for `carbide-build-minimal`. |
| **Full build Dockerfile** | `dev/docker/Dockerfile.build-container-x86_64` | Defines the full build image (Rust 1.90, PostgreSQL, protobuf, TSS, etc.). |

All commands below are run from the **repository root** unless noted.

---

## Prerequisites

1. **Docker**  
   Docker Desktop for Mac (or another Docker runtime) installed and running.

2. **cargo-make**  
   Used to run the Makefile tasks. Install if needed:
   ```bash
   cargo install cargo-make
   ```

3. **CARGO_HOME (optional but recommended)**  
   So the container can reuse your Cargo cache:
   ```bash
   export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
   ```

---

## Tests to run before build

Use these to validate changes (e.g. IB partition update) before building the Docker image or doing a full build.

### Option A: Quick check (no database)

Verifies that the API and deps compile. No Postgres needed.

```bash
# From repo root
cargo make cargo-docker-minimal -- check -p carbide-api --no-default-features
```

If you haven’t built the minimal image yet, build it first: `cargo make build-cargo-docker-image-minimal`.

### Option B: IB partition tests (need PostgreSQL)

These tests use a real database. Start Postgres, set `DATABASE_URL`, then run the tests.

**1. Start Postgres (if not already running):**

```bash
docker compose up -d postgresql
```

**2. Run IB partition tests:**

**Locally (Rust 1.90 + `DATABASE_URL`):**

```bash
export DATABASE_URL="postgres://carbide_development:notforprod@localhost:5432/carbide_development"
cargo test -p carbide-api ib_partition --no-default-features --no-fail-fast
```

**Via minimal Docker image (after `build-cargo-docker-image-minimal`):**

```bash
export DATABASE_URL="postgres://carbide_development:notforprod@host.docker.internal:5432/carbide_development"
cargo make cargo-docker-minimal -- test -p carbide-api ib_partition --no-default-features --no-fail-fast
```

Use `host.docker.internal` so the container can reach Postgres on the host (Docker Desktop for Mac supports this; the minimal image includes `libpq-dev` for the Postgres client).

### Suggested order before a build

1. Run **Option A** (check) to ensure everything compiles.
2. If you changed API or DB code, run **Option B** (ib_partition tests) with Postgres and `DATABASE_URL` set.
3. Then run your full build (e.g. `cargo make cargo-docker-minimal -- build -p carbide-admin-cli --release`).

---

## Quick start (recommended on Mac)

Use the **minimal** path. The workspace (including `carbide-rpc`) needs **`protoc`** to compile `.proto` files, so you build a small image once (~2–5 min) that adds only Rust + protoc.

**First time only — build the minimal image:**

```bash
# From repo root
cd /path/to/bare-metal-manager-core

cargo make build-cargo-docker-image-minimal
```

**Then run Cargo as needed:**

```bash
# Build admin-cli (default command)
cargo make cargo-docker-minimal

# Or pass a custom cargo command (each argument after --; do not wrap in quotes)
cargo make cargo-docker-minimal -- build -p carbide-admin-cli --release
cargo make cargo-docker-minimal -- check -p carbide-api --no-default-features
```

Output binaries appear under `target/` in your repo as usual.

---

## How to use: Minimal path (`cargo-docker-minimal`)

**When to use:** Day-to-day builds and checks on macOS when you don’t need the full API test stack (PostgreSQL, TSS, etc.).

**What it uses:** The image `carbide-build-minimal` (Rust 1.90 + `protoc`). You must build it once with `build-cargo-docker-image-minimal` (~2–5 min). The `carbide-rpc` crate needs `protoc` and the Google well-known proto files (`libprotobuf-dev`), so the bare `rust:1.90.0-slim-bookworm` image is not enough for workspace builds.

### Usage

```bash
# Default: build admin-cli in release mode
cargo make cargo-docker-minimal

# Custom cargo command (pass each argument after --; do not wrap in quotes)
cargo make cargo-docker-minimal -- build -p carbide-admin-cli --release
cargo make cargo-docker-minimal -- check -p carbide-api --no-default-features
cargo make cargo-docker-minimal -- build -p carbide-api --no-default-features
```

### What works

- Building **carbide-admin-cli**.
- Building/checking **carbide-api** with `--no-default-features` (avoids `tss-esapi` and other heavy deps).
- Other crates that don’t need PostgreSQL, protobuf, or TSS.

### What doesn’t work

- Full **carbide-api** with default features (needs TSS/measured-boot stack).
- API tests that require a database (slim image has no PostgreSQL client libs). For those, use the full image path below or run tests elsewhere (e.g. CI).

---

## How to use: Full image path (`build-cargo-docker-image` + `cargo-docker`)

**When to use:** When you need the full environment (e.g. run API tests with PostgreSQL, or build with default features). On Apple Silicon the image build is slow (45+ minutes); prefer the minimal path for routine work.

### Step 1: Build the image (once)

```bash
cargo make build-cargo-docker-image
```

Or manually:

```bash
docker build -f dev/docker/Dockerfile.build-container-x86_64 -t carbide-build-x86_64 dev/docker
```

On Apple Silicon this runs under emulation and can take a long time; step 7 (installing cargo tools) alone often takes 45+ minutes.

### Step 2: Run Cargo in the full container

```bash
# Build admin-cli
cargo make cargo-docker -- build -p carbide-admin-cli --release

# Run API tests (set DATABASE_URL if tests need Postgres)
export DATABASE_URL="postgres://carbide_development:notforprod@host.docker.internal:5432/carbide_development"
cargo make cargo-docker -- test -p carbide-api ib_partition --no-fail-fast
```

For tests that need Postgres, start it first (e.g. `docker compose up -d postgresql`) and use `host.docker.internal` in `DATABASE_URL` so the container can reach the host’s Postgres.

---

## Command reference

| Goal | Command |
|------|--------|
| Build minimal image once (Rust + protoc; ~2–5 min) | `cargo make build-cargo-docker-image-minimal` |
| Build admin-cli (minimal) | `cargo make cargo-docker-minimal` |
| Build admin-cli release (minimal) | `cargo make cargo-docker-minimal -- build -p carbide-admin-cli --release` |
| Check API without default features (minimal) | `cargo make cargo-docker-minimal -- check -p carbide-api --no-default-features` |
| Build full repo image (once, slow on Mac) | `cargo make build-cargo-docker-image` |
| Build admin-cli (full image) | `cargo make cargo-docker -- build -p carbide-admin-cli --release` |
| Run API tests (full image; set DATABASE_URL) | `cargo make cargo-docker -- test -p carbide-api ib_partition --no-fail-fast` |

---

## When to use which option

| Use case | Option |
|----------|--------|
| Build admin-cli on Mac | **cargo-docker-minimal** |
| Check or build API without TSS/measured-boot | **cargo-docker-minimal** with `--no-default-features` |
| Run API tests that need PostgreSQL | **build-cargo-docker-image** then **cargo-docker** (and set DATABASE_URL) |
| Build or test with full API default features | **build-cargo-docker-image** then **cargo-docker** |

---

## Tips and troubleshooting

1. **Cargo cache**  
   The tasks mount `CARGO_HOME` (e.g. `$HOME/.cargo`) into the container so dependency builds are cached on your Mac.

2. **File ownership**  
   The container runs as your user (`id -u` / `id -g`), so generated files under `target/` are owned by you.

3. **Postgres for API tests**  
   Start Postgres (e.g. `docker compose up -d postgresql`), then set:
   ```bash
   export DATABASE_URL="postgres://carbide_development:notforprod@host.docker.internal:5432/carbide_development"
   ```
   Use **`host.docker.internal`** (not `localhost`) so the container can reach Postgres on the host. `cargo-docker-minimal` passes `DATABASE_URL` into the container when set.

4. **Docker or tests hang**  
   - **DB tests:** If `DATABASE_URL` is unset or uses `localhost`, the container cannot reach Postgres and tests can hang. Set `DATABASE_URL` with `host.docker.internal` as the host (see above).  
   - **Stuck containers:** Stop them with `docker ps` then `docker stop <container_name>` or `docker rm -f <container_name>`.  
   - **Timeout:** Run tests with a time limit so they don’t hang indefinitely:
     - **Linux:** `timeout 300 cargo make cargo-docker-minimal -- test ...`
     - **macOS:** Install GNU coreutils then use `gtimeout`, or run without timeout and set `DATABASE_URL` so DB tests don’t hang:
       ```bash
       brew install coreutils   # one-time; provides gtimeout
       export DATABASE_URL="postgres://carbide_development:notforprod@host.docker.internal:5432/carbide_development"
       gtimeout 300 cargo make cargo-docker-minimal -- test -p carbide-api ib_partition --no-default-features --no-fail-fast
       ```
     (300 seconds = 5 minutes; adjust as needed.)

5. **Apple Silicon**  
   The full build image is x86_64 and runs under emulation, so it is slow. Use **cargo-docker-minimal** for daily work; use the full image only when you need it.

6. **`protoc` required for workspace builds**  
   The `carbide-rpc` crate compiles `.proto` files and needs the Protocol Buffers compiler (`protoc`). The minimal image adds only that; the full image includes it as well.

7. **Running without cargo-make**  
   You can run the same `docker run` locally. The minimal variant (after building `carbide-build-minimal` once); add `-e DATABASE_URL="$DATABASE_URL"` when running tests that need the DB:
   ```bash
   docker run --rm \
     -v "$(pwd)":/code \
     -v "${CARGO_HOME:-$HOME/.cargo}":/cargo \
     -w /code \
     -u "$(id -u):$(id -g)" \
     -e CARGO_HOME=/cargo \
     ${DATABASE_URL:+-e DATABASE_URL="$DATABASE_URL"} \
     carbide-build-minimal \
     cargo build -p carbide-admin-cli --release
   ```
