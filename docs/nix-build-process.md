# Carbide build process — Nix

How to build carbide binaries, containers, and iPXE artifacts locally
using the Nix flake.

## Prerequisites

- Nix installed (Determinate installer recommended).
- For aarch64 targets from an x86 host: aarch64 builder configured.
  See [`nix-aarch64-builder-setup.md`](./nix-aarch64-builder-setup.md).
- Files must be git-tracked (at least `git add`ed) before `nix build`
  can see them.

## Rust binaries

```sh
# Native binaries (x86_64 on x86_64 host, aarch64 on aarch64 host)
nix build .#carbide-api
nix build .#carbide-dns
nix build .#carbide-pxe
nix build .#carbide-dhcp
nix build .#carbide-health
nix build .#carbide-ssh-console
nix build .#nico-admin-cli
nix build .#carbide-scout

# aarch64 cross-compiled binaries (from any host)
nix build .#forge-dpu-agent
nix build .#forge-dhcp-server
nix build .#carbide-fmds
nix build .#carbide-dpf
nix build .#carbide-scout-aarch64
```

Each produces `result/bin/<binary-name>`.

## Go binaries (rest-api)

```sh
# amd64
nix build .#rest-api-api
nix build .#rest-api-workflow
nix build .#rest-api-sitemgr
nix build .#rest-api-site-agent
nix build .#rest-api-migrations
nix build .#rest-api-credsmgr
nix build .#rest-api-nicocli

# arm64 (suffix -aarch64)
nix build .#rest-api-api-aarch64
nix build .#rest-api-nicocli-aarch64
# ... same pattern for the rest
```

## Container images

Each service has a corresponding container built with nix2container:

```sh
nix build .#carbide-api-container
nix build .#carbide-dns-container
nix build .#carbide-dhcp-container
# ... one per native binary
```

The result is an OCI image JSON manifest (not a tarball). To load into
the local Docker daemon:

```sh
nix run .#carbide-api-container-copy-to-docker
nix run .#carbide-dns-container-copy-to-docker
```

This copies via the patched `skopeo-nix2container` using the `nix:`
transport and also tags the image as `:latest`.


## iPXE EFI

```sh
nix build .#ipxe-efi-x86
nix build .#ipxe-efi-aarch64
```

Both can be built from an x86_64 host. `ipxe-efi-aarch64` is
cross-compiled.

## Warming the dep cache

```sh
nix build .#deps
```

Builds only the external dependency phase (`cargoArtifacts`). Useful
for warming a binary cache after `Cargo.lock` changes, without
triggering a full binary rebuild in CI.

## Cache invalidation

| Change | `deps` | binary builds |
|---|---|---|
| Edit a `.rs` file | cache hit | rebuild (~2-3 min) |
| Edit docs, helm, nix files | cache hit | cache hit |
| Add/bump a dep in `Cargo.lock` | **rebuild** (~15 min) | rebuild |
| First build / cold cache | build (~15 min) | build |

## Reference

- `flake.nix` — all package, app, and container definitions
- `nix/rust/crate-binary.nix` — `mkCrateBinary` implementation
- `nix/rust/cross-crate-binary-aarch64.nix` — `mkCrossCrateBinary`
- `nix/container/make-container.nix` — `mkContainer` implementation
- `nix/container/oss-sources.nix` — OSS source bundling
- `nix/boot/ipxe-x86.nix`, `nix/boot/ipxe-aarch64.nix` — iPXE builds
- `docs/nix-aarch64-builder-setup.md` — aarch64 builder provisioning
