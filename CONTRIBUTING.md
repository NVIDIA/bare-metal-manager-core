# Contributing to NCX Infra Controller

Thank you for your interest in contributing to NCX Infra Controller! 

We welcome contributions of all sizes — from fixing a typo in the docs to adding a new API endpoint. Whether you're a first-time contributor or a seasoned open source developer, there's a place for you here.

> **Project Status:** NCX Infra Controller is currently in **experimental**. This means:
>
> - APIs, configurations, and features may change without notice between releases.
> - Review timelines may vary as the team focuses on stabilizing the core platform.
> - Not all contributions will be accepted — we prioritize changes that align with the current roadmap.
>
> We appreciate your patience and contributions as we work toward a stable release.

## Table of Contents

- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Fork and Setup](#fork-and-setup)
- [Contribution Process](#contribution-process)
- [Pull Request Guidelines](#pull-request-guidelines)

## Developer Certificate of Origin (DCO)

NCX Infra Controller requires the Developer Certificate of Origin (DCO) process to be followed for all contributions.

The DCO is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing. The full text of the DCO can be found at [developercertificate.org](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Signing Your Commits

To sign off on a commit, you must add a `Signed-off-by` line to your commit message. This is done by using the `-s` or `--signoff` flag when committing:

```bash
git commit -s -m "Your commit message"
```

**Tip:** You can create a Git alias to always sign off:

```bash
git config --global alias.ci 'commit -s'
# Now use: git ci -m "Your commit message"
```

This will automatically add a line like this to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Make sure your `user.name` and `user.email` are set correctly in your Git configuration:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Signing Off Multiple Commits

If you have multiple commits that need to be signed off, you can use interactive rebase:

```bash
git rebase HEAD~<number_of_commits> --signoff
```

Or to sign off all commits in a branch:

```bash
git rebase --signoff origin/main
```

### DCO Enforcement

All pull requests are automatically checked for DCO compliance via DCO bot. Pull requests with unsigned commits cannot be merged until all commits are properly signed off.

## Fork and Setup

Developers must first fork the upstream [NCX Infra Controller repository](https://github.com/NVIDIA/ncx-infra-controller-core).

### 1. Fork the Repository

1. Navigate to the [NCX Infra Controller repository](https://github.com/NVIDIA/ncx-infra-controller-core) on GitHub.
2. Click the **Fork** button in the upper right corner.
3. Select your GitHub account as the destination.

### 2. Clone Your Fork

```bash
git clone https://github.com/<your-username>/metal-manager.git
cd metal-manager
```

### 3. Add Upstream Remote

Add the original repository as an upstream remote to keep your fork in sync:

```bash
git remote add upstream https://github.com/NVIDIA/metal-manager.git
git remote -v  # Verify remotes
```

### 4. Keep Your Fork Updated

Before starting new work, sync your fork with upstream:

```bash
# Fetch upstream changes
git fetch upstream

# Switch to main branch
git checkout main

# Merge upstream changes
git merge upstream/main

# Push to your fork
git push origin main
```

### 5. Create a Feature Branch

Always create a new branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names like:
- `feature/add-new-api`
- `fix/resolve-dhcp-issue`
- `docs/update-readme`

## Contribution Process

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** following our coding guidelines.
3. **Sign off all your commits** using `git commit -s`.
4. **Submit a pull request** with a clear description of your changes.

## Pull Request Guidelines

- Provide a clear description of the problem and solution.
- Reference any related issues.
- Keep pull requests focused on a single change.
- Be responsive to feedback and code review comments.
- Ensure all CI checks pass before requesting review.

## Updating Pinned Dependencies

### Git submodules

Two git submodules are pinned to known-good versions:

| Submodule | Path | Pinned version |
|-----------|------|----------------|
| mkosi | `pxe/mkosi` | `v25` |
| iPXE (secboot fork) | `pxe/ipxe/upstream` | `secboot-ioactive-20221109-302-gd7e58c5a8` |

To update a submodule to a newer version:

```bash
cd pxe/mkosi          # or pxe/ipxe/upstream
git fetch
git checkout <new-tag-or-commit>
cd ../..
git add pxe/mkosi     # or pxe/ipxe/upstream
git commit -s -m "chore: bump mkosi to <new-version>"
```

After bumping, validate with a full PXE artifact build:

```bash
cargo make build-pxe-build-container   # rebuild if Dockerfile changed
cargo make pxe-docker-x86
```

### Rust toolchain

The Rust compiler version is pinned in `rust-toolchain.toml`. To update, change the version there and update the `RUST_VERSION` ARG in `dev/docker/Dockerfile.pxe-build-container` to match.

## Basic Testing the NICo Image

After building the `nico` release image, run a quick sanity check to confirm all binaries are
present and start without crashing:

```bash
for bin in carbide carbide-admin-cli carbide-api carbide-dns carbide-dsx-exchange-consumer \
           forge-dhcp-server forge-dpu-agent forge-hw-health forge-log-parser ssh-console; do
  echo "$bin: $(docker run --rm nico /opt/carbide/$bin --help 2>&1 | head -1)"
done
```

Each line should print a usage string or a startup log line. Services that don't implement
`--help` (e.g. `carbide-dsx-exchange-consumer`, `forge-hw-health`) will log their startup config
and then block waiting for connections — that is expected and counts as a pass. Any
`exec format error` or `No such file` indicates a broken build.

## Build Optimizations and Trade-offs

The Docker release image build (`Dockerfile.release-container-sa-x86_64`) includes several
non-obvious optimizations. This section documents the intent and trade-offs so future maintainers
understand why the build is structured the way it is.

### `debug = "line-tables-only"` in the release profile

**What it does:** The release profile uses `debug = "line-tables-only"` instead of the Rust default
(`debug = 0`) or full debug info (`debug = true`). This embeds line-number tables in binaries but
omits DWARF variable info (local variable names, types, values).

**Why:** With `debug = true`, the `carbide-api` binary alone was ~1.46 GB, producing a 5.4 GB
release image. `"line-tables-only"` reduced the binary to ~544 MB and the image to ~2.5 GB —
a 58% reduction — while keeping stack traces useful (line numbers are preserved).

**Trade-off:** Debuggers (gdb/lldb) and core dump analysis will show the call stack with line
numbers but will not be able to inspect local variable values. For production debugging this is
usually acceptable because we rely on structured logging and tracing rather than debugger sessions.
If you need full variable inspection (e.g., for post-mortem core analysis of a reproduction), build
locally with `debug = true` in a `[profile.dev]` override or a local `Cargo.toml` override.

### `--no-workspace` on `clippy-release` and `build-release`

**What it does:** Both tasks are invoked with `cargo make --no-workspace` in the Dockerfile.
Without this flag, cargo-make iterates all workspace members (64 crates) and calls `cargo build`
or `cargo clippy` once per crate. With `--no-workspace`, cargo-make runs the task once at the
workspace root, which is equivalent to running `cargo build --workspace` — a single invocation
that builds everything once.

**Why:** The per-member iteration caused shared dependencies (`tonic`, `sqlx`, `carbide-rpc`, etc.)
to be recompiled repeatedly across members. Switching to `--no-workspace` reduced the build from
~98 minutes to ~21 minutes on a 72-core server.

**Trade-off:** Per-crate feature isolation is lost. Cargo unifies features across all workspace
members at once rather than resolving each crate independently. For this project all crates ship
together as a single release image, so cross-crate feature conflicts are not a concern. If you
ever extract a crate for standalone deployment, validate its feature set independently with
`cargo build -p <crate>`.

### `clippy-release` shares artifacts with `build-release`

**What it does:** The `clippy-release` Makefile task runs clippy with `--release`, and
`build-release` also compiles in release mode. Because they share the same compilation flags and
profile, the compiled `.rlib` and `.rmeta` artifacts from the clippy step are reused by the build
step — no second compile of all 64 crates.

**Trade-off:** `clippy-release` passes `--all-targets`, which includes test and benchmark targets
that `build-release` does not compile. Clippy therefore lints slightly more code than is shipped
in the final binary. In practice this is a net benefit (broader coverage), but if a test-only
dependency activates features that interact unexpectedly with production code, the lint results
may differ from a targeted per-crate clippy run.

## Questions?

If you have questions about contributing, please open an issue for discussion.
