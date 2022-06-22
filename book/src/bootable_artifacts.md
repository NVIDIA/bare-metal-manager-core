# Generating bootable artifacts

### Building the ephemeral image
in the `pxe/` subdirectory, run `cargo make`. You may need to install `liblzma-dev` and `gcc-aarch64-linux-gnu`

```
cargo make ipxe
cargo make create-ephemeral-image
```

and this should make and populate a directory in `pxe/static` and should have the following files therein.

```
static/
└── blobs
    └── internal
        ├── aarch64
        │   └── ipxe.efi
        └── x86_64
            ├── carbide.efi
            ├── carbide.root
            ├── ipxe.efi
            └── ipxe.kpxe
```

