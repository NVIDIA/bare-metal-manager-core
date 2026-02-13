# Building BMM Containers

This section provides instructions for building the containers for NVIDIA Bare Metal Manager (BMM).

## Installing Prerequisite Software

Before you begin, ensure you have the following prerequisites:

* An Ubuntu 24.04 Host or VM with 150GB+ of disk space (MacOS is not supported)

Use the following steps to install the prerequisite software on the Ubuntu Host or VM. These instructions
assume an `apt`-based distribution such as Ubuntu 24.04.

1. `apt-get install build-essential direnv mkosi uidmap curl fakeroot git docker.io docker-buildx sccache protobuf-compiler libopenipmi-dev libudev-dev libboost-dev libgrpc-dev libprotobuf-dev libssl-dev libtss2-dev kea-dev systemd-boot systemd-ukify`
2. [Add the correct hook for your shell](https://direnv.net/docs/hook.html)
3. Install rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (select Option 1)
4. Start a new shell to pick up changes made from direnv and rustup.
5. Clone BMM - `git clone git@github.com:NVIDIA/bare-metal-manager-core.git bare-metal-manager`
6. `cd bare-metal-manager`
7. `direnv allow`
8. `cd $REPO_ROOT/pxe`
9. `git clone https://github.com/systemd/mkosi.git`
10. `cd mkosi && git checkout 26673f6`
11. `cd $REPO_ROOT/pxe/ipxe`
12. `git clone https://github.com/ipxe/ipxe.git upstream`
13. `cd upstream && git checkout d7e58c5`
14. `sudo systemctl enable docker.socket`
15. `cd $REPO_ROOT`
16. `cargo install cargo-make cargo-cache`
17. `echo "kernel.apparmor_restrict_unprivileged_userns=0" | sudo tee /etc/sysctl.d/99-userns.conf`
18. `sudo usermod -aG docker <username>`
19. `reboot`

**NOTE**: To download the required HBN container, you must have access to [PID Library](https://apps.nvidia.com/pid/contentlibraries/detail?id=1138607). The PID Library contains the attachment `HBN-LTS-2-4-3-complete.tar.gz`, which you will need to download into your home directory.

## Building X86_64 Containers

**NOTE**: Execute these tasks in order. All commands are run from the top of the `bare-metal-manager` directory.

### Building the X86 build container

```sh
docker build --file dev/docker/Dockerfile.build-container-x86_64 -t bmm-buildcontainer-x86_64 .
```

### Building the X86 runtime container

```sh
docker build --file dev/docker/Dockerfile.runtime-container-x86_64 -t bmm-runtime-container-x86_64 .
```

### Building the boot artifact containers

```sh
cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-x86-host-sa
docker build --build-arg "CONTAINER_RUNTIME_X86_64=alpine:latest" -t boot-artifacts-x86_64 -f dev/docker/Dockerfile.release-artifacts-x86_64 .
```

## Building the Machine Validation images

```sh
docker build --build-arg CONTAINER_RUNTIME_X86_64=bmm-runtime-container-x86_64 -t machine-validation-runner -f dev/docker/Dockerfile.machine-validation-runner .

docker save --output crates/machine-validation/images/machine-validation-runner.tar machine-validation-runner:latest 

// This copies `machine-validation-runner.tar` into the `/images` directory on the `machine-validation-config` container.  When using a kubernetes deployment model
// this is the only `machine-validation` container you need to configure on the `carbide-pxe` pod.

docker build --build-arg CONTAINER_RUNTIME_X86_64=bmm-runtime-container-x86_64 -t machine-validation-config -f dev/docker/Dockerfile.machine-validation-config .

```

## Building bmm-core container

```sh
docker build --build-arg "CONTAINER_RUNTIME_X86_64=bmm-runtime-container-x86_64" --build-arg "CONTAINER_BUILD_X86_64=bmm-buildcontainer-x86_64" -f dev/docker/Dockerfile.release-container-sa-x86_64 -t bmm .
```

## Building the AARCH64 Containers and artifacts

### Building the Cross-compile container

```sh
docker build --file dev/docker/Dockerfile.build-artifacts-container-cross-aarch64 -t build-artifacts-container-cross-aarch64 .
```

### Building the DPU BFB

After downloading `HBN-LTS-2-4-3-complete.tar.gz`, perfrom the following steps:

```sh
tar -zxf HBN-LTS-2-4-3-complete.tar.gz`
cd HBN-LTS-2-4-3
cp hbn-lts-2-4-3.tar /tmp/doca_hbn.tar
cd doca_container_configs_v2.10.81
zip -r ../doca_container_configs.zip .
cp doca_container_configs.zip /tmp
```

```sh
cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-bfb-sa

docker build --build-arg "CONTAINER_RUNTIME_AARCH64=alpine:latest" -t boot-artifacts-aarch64 -f dev/docker/Dockerfile.release-artifacts-aarch64 .
```

**NOTE**: The `CONTAINER_RUNTIME_AARCH64=alpine:latest` build argument must be included. The aarch64 binaries are bundled into an x86 container.
