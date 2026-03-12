# Running Cargo via Docker on macOS

When Cargo doesn't work well natively on macOS (e.g. Rust version mismatch, `tss-esapi` / platform issues), you can build and test using Docker so everything runs in a Linux environment with the correct Rust toolchain.

## Prerequisites

- **Docker Desktop for Mac** (or another Docker runtime) installed and running.
- **CARGO_HOME** set (e.g. `export CARGO_HOME=$HOME/.cargo`) so the container can reuse your Cargo cache.

---

## Option 1: Use the repo's build container (full environment)

The repo has a Linux build image that matches `rust-toolchain.toml` (Rust 1.90) and includes PostgreSQL, protobuf, and other deps.

### 1. Build the image once (from repo root)

```bash
docker build -f dev/docker/Dockerfile.build-container-x86_64 -t carbide-build-x86_64 dev/docker
```

On Apple Silicon this uses emulation and can take a while. Use it for full `cargo build` / `cargo test` that need all dependencies.

### 2. Run Cargo inside the container

**Build a package (e.g. admin-cli):**

```bash
docker run --rm \
  -v "$(pwd)":/code \
  -v "${CARGO_HOME:-$HOME/.cargo}":/cargo \
  -w /code \
  -u "$(id -u):$(id -g)" \
  -e CARGO_HOME=/cargo \
  carbide-build-x86_64 \
  cargo build -p carbide-admin-cli --release
```

**Run tests (e.g. API, with database):**

Start Postgres first (e.g. via docker-compose), then pass `DATABASE_URL`:

```bash
# Terminal 1: start Postgres
docker compose up -d postgresql

# Terminal 2: run tests (use host postgres from host; or use a URL reachable from inside the container)
export DATABASE_URL="postgres://carbide_development:notforprod@host.docker.internal:5432/carbide_development"

docker run --rm \
  -v "$(pwd)":/code \
  -v "${CARGO_HOME:-$HOME/.cargo}":/cargo \
  -w /code \
  -u "$(id -u):$(id -g)" \
  -e CARGO_HOME=/cargo \
  -e DATABASE_URL \
  --add-host=host.docker.internal:host-gateway \
  carbide-build-x86_64 \
  cargo test -p carbide-api ib_partition --no-fail-fast
```

On Docker Desktop for Mac, `host.docker.internal` and `--add-host=host.docker.internal:host-gateway` let the container reach Postgres on the host.

---

## Option 2: Minimal Rust image (quick builds, no full deps)

For simple `cargo build` (e.g. admin-cli) without building the full repo image, use the official Rust image that matches `rust-toolchain.toml`:

```bash
docker run --rm \
  -v "$(pwd)":/code \
  -v "${CARGO_HOME:-$HOME/.cargo}":/cargo \
  -w /code \
  -u "$(id -u):$(id -g)" \
  -e CARGO_HOME=/cargo \
  rust:1.90.0-slim-bookworm \
  cargo build -p carbide-admin-cli --release
```

This image does **not** include PostgreSQL, protobuf, or TSS libs, so some crates (e.g. full `carbide-api` with default features) may still fail to build. Use for crates that don’t need those.

---

## Option 3: Makefile tasks (if added)

From repo root you can use:

```bash
# Build the repo build image (once)
cargo make build-cargo-docker-image

# Run a cargo command in Docker (example: build admin-cli)
cargo make cargo-docker -- "build -p carbide-admin-cli --release"

# Run tests in Docker (example: ib_partition tests; set DATABASE_URL if needed)
cargo make cargo-docker -- "test -p carbide-api ib_partition --no-fail-fast"
```

---

## Tips

1. **Cache:** Mounting `CARGO_HOME` (e.g. `-v $HOME/.cargo:/cargo`) keeps the container’s Cargo cache on your Mac so later runs are faster.
2. **Ownership:** `-u "$(id -u):$(id -g)"` keeps generated files owned by your user.
3. **Postgres for tests:** For API tests that need a DB, run Postgres on the host (e.g. `docker compose up -d postgresql`) and use `DATABASE_URL=...@host.docker.internal:5432/...` when running the test container.
4. **Apple Silicon:** The repo’s build image is x86_64; Docker will emulate it. For faster builds you can try a smaller `rust:1.90` image and only build the packages you need.
