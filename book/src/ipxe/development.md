## IPXE image building workflow

This workflow assumes that you have already gone through the docker-compose workflow at least once, and are now ready to test a working qemu image against your local carbide API install, typically as part of validating code changes locally. The first 3 steps are required as part of the very first setup, the last one is the one you can do repeatedly to validate that you haven't broken anything.

### 1. Install build tools

Install 'mkosi' and 'debootstrap' from repository -- for Debian it was
```
sudo apt install mkosi debootstrap
```

### 2. Build IPXE image

Run
```
cd $CARBIDE_ROOT_DIR/pxe && && cargo make build-boot-artifacts-x86_64
```
or
```
cd $CARBIDE_ROOT_DIR/pxe && cargo make create-ephemeral-image && cargo make ipxe-x86_64
```

`build-boot-artifacts-x86_64` will also rebuild binaries that
we package as part of the boot artifacts (like `carbide-cli`), while
the latter command will only package already existing artifacts.
Therefore prefer the former if you change applications.

**Note:** the last step will exit uncleanly because it wants to compress for CI/CD and upload but it's not necessary locally.  It's fine as long as the contents of this directory look similar to:
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
**Note:** you'll also need to chown the directory recursively back to your user because mkosi will only run as root, otherwise your next docker-compose build won't have the permissions it needs:
```
sudo chown -R `whoami` pxe/static/*
```

### 3. PXE boot the image in a VM

To start a VM that PXE boots from the image you just built,
bounce your docker-compose or KIND setup and follow the steps in
[Running a PXE Client in a VM](../development/vm_pxe_client.md)
