# Generating bootable artifacts

### 1. Install build tools

Install 'mkosi' and 'debootstrap' from the repository -- for Debian it was

```
sudo apt install mkosi debootstrap
```

### 2. Build IPXE image

Run

```
cd $CARBIDE_ROOT_DIR/pxe && cargo make build-boot-artifacts-x86_64
```

Because you cannot build `aarch64` artifacts on an `x86_64` host, we only create the necessary directories to satisfy the `docker-compose` workflow:

```
cd $CARBIDE_ROOT_DIR/pxe && cargo make mkdir-static-aarch64
```

**NOTE**

> Running Forge using `docker-compose` and QEMU `clients` only works with `x86_64` binaries. For testing on `aarch64` systems such as a Bluefield
> we rely on CI/CD configured in `carbide` gitlab repo.

or

download pre-built artifacts - ideal if the `ipxe-x86_64` gives you
errors. Extract the latest [from Artifactory](https://urm.nvidia.com/ui/native/swngc-ngcc-generic-local/nvmetal/boot-artifacts/x86_64/)
into `$CARBIDE_ROOT_DIR/pxe/static/blobs/internal/x86_64/` (you'll need
to create the hierarchy).

`build-boot-artifacts-x86_64` will also rebuild binaries we package as part of the boot artifacts (like `forge-scout`), while
the latter command will only package already existing artifacts.
Therefore prefer the former if you change applications.

**Note:** the last step will exit uncleanly because it wants to compress for CI/CD and upload, but it's not necessary locally. It's fine as long as the contents of this directory look similar to:

```
$ exa -alh pxe/static/blobs/internal/x86_64/
Permissions Size User      Date Modified Name
.rw-rw-r--    44 $USER     18 Aug 15:35  .gitignore
drwxr-xr-x     - $USER     24 Aug 09:59  .mkosi-t40tggmu
.rw-r--r--   55M $USER     24 Aug 10:01  carbide.efi
.rw-r--r--   26k $USER     24 Aug 10:01  carbide.manifest
.rw-r--r--  298M $USER     24 Aug 10:01  carbide.root
.rw-rw-r--  1.1M $USER     24 Aug 10:05  ipxe.efi
.rw-rw-r--  402k $USER     24 Aug 10:03  ipxe.kpxe
```

**Note:** you'll also need to `chown` the directory recursively back to
your user because mkosi will only run as root; otherwise, your next
docker-compose build won't have the permissions it needs:

```
sudo chown -R `whoami` pxe/static/*
```
