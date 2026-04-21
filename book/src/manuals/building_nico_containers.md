# Building NICo Containers

This section provides instructions for building the containers for NCX Infra Controller (NICo).
For the complete deployment workflow, refer to the [End-to-End Installation Guide](installation-guide.md).

## Container Image Summary

The following table lists all container images produced by this build process:

| Image Name | Dockerfile | Purpose | Architecture |
|------------|-----------|---------|-------------|
| `nico-buildcontainer-x86_64` | `dev/docker/Dockerfile.build-container-x86_64` | Intermediate build container (Rust toolchain, libraries) | x86_64 |
| `nico-runtime-container-x86_64` | `dev/docker/Dockerfile.runtime-container-x86_64` | Intermediate runtime base image | x86_64 |
| `nico` (nvmetal-carbide) | `dev/docker/Dockerfile.release-container-sa-x86_64` | Carbide API, DHCP, DNS, PXE, hardware health, SSH console | x86_64 |
| `boot-artifacts-x86_64` | `dev/docker/Dockerfile.release-artifacts-x86_64` | PXE boot artifacts for x86 hosts | x86_64 |
| `boot-artifacts-aarch64` | `dev/docker/Dockerfile.release-artifacts-aarch64` | PXE boot artifacts for DPU BFB provisioning | x86_64 (bundles aarch64 binaries) |
| `machine-validation-runner` | `dev/docker/Dockerfile.machine-validation-runner` | Machine validation / burn-in test runner | x86_64 |
| `machine-validation-config` | `dev/docker/Dockerfile.machine-validation-config` | Machine validation config (bundles runner tar) | x86_64 |
| `build-artifacts-container-cross-aarch64` | `dev/docker/Dockerfile.build-artifacts-container-cross-aarch64` | Intermediate cross-compile container for aarch64 | x86_64 |

The intermediate images (`nico-buildcontainer-x86_64`, `nico-runtime-container-x86_64`,
`build-artifacts-container-cross-aarch64`) are used during the build process and do not
need to be pushed to your registry. The remaining images must be pushed to a registry
accessible by your Kubernetes cluster.

## Installing Prerequisite Software

Before you begin, ensure you have the following prerequisites:

* An Ubuntu 24.04 Host or VM with 150GB+ of disk space (MacOS is not supported)
* For REST containers: Go (refer to the `go.mod` file in the [REST repo](https://github.com/NVIDIA/ncx-infra-controller-rest) for the current required version), Docker 20.10+ with BuildKit enabled
* An [NVIDIA NGC](https://www.nvidia.com/en-us/gpu-cloud/) account (free). Required for pulling base images such as the DOCA HBN container used in the aarch64/DPU BFB build. Sign up at [ngc.nvidia.com](https://ngc.nvidia.com) and generate an API key under **API Keys** > **Generate Personal Key**.

Use the following steps to install the prerequisite software on the Ubuntu Host or VM. These instructions
assume an `apt`-based distribution such as Ubuntu 24.04.

1. `apt-get install build-essential cpio direnv mkosi uidmap curl file fakeroot git docker.io docker-buildx sccache protobuf-compiler libopenipmi-dev libudev-dev libboost-dev libgrpc-dev libprotobuf-dev libssl-dev libtss2-dev kea-dev systemd-boot systemd-ukify jq zip`
2. [Add the correct hook for your shell](https://direnv.net/docs/hook.html)
3. Install rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (select Option 1)
4. Start a new shell to pick up changes made from direnv and rustup.
5. Clone NICo - `git clone git@github.com:NVIDIA/ncx-infra-controller-core.git ncx-infra-controller`
6. `cd ncx-infra-controller`
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


## Building X86_64 Containers

**NOTE**: Execute these tasks in order. All commands are run from the top of the `ncx-infra-controller` directory.

### Building the X86 build container

```sh
docker build --file dev/docker/Dockerfile.build-container-x86_64 -t nico-buildcontainer-x86_64 .
```

### Building the X86 runtime container

```sh
docker build --file dev/docker/Dockerfile.runtime-container-x86_64 -t nico-runtime-container-x86_64 .
```

### Building the boot artifact containers

```sh
cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-x86-host-sa
docker build --build-arg "CONTAINER_RUNTIME_X86_64=alpine:latest" -t boot-artifacts-x86_64 -f dev/docker/Dockerfile.release-artifacts-x86_64 .
```

## Building the Machine Validation Images

```sh
docker build --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 \
  -t machine-validation-runner -f dev/docker/Dockerfile.machine-validation-runner .

docker save --output crates/machine-validation/images/machine-validation-runner.tar \
  machine-validation-runner:latest

docker build --build-arg CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64 \
  -t machine-validation-config -f dev/docker/Dockerfile.machine-validation-config .
```

The `machine-validation-config` container bundles `machine-validation-runner.tar` into its
`/images` directory. In a Kubernetes deployment, this is the only machine-validation
container you need to configure on the `carbide-pxe` pod.

## Building nico-core Container

```sh
docker build \
  --build-arg "CONTAINER_RUNTIME_X86_64=nico-runtime-container-x86_64" \
  --build-arg "CONTAINER_BUILD_X86_64=nico-buildcontainer-x86_64" \
  -f dev/docker/Dockerfile.release-container-sa-x86_64 \
  -t nico .
```

## Building the AARCH64 Containers and Artifacts

### Building the Cross-compile container

```sh
docker build --file dev/docker/Dockerfile.build-artifacts-container-cross-aarch64 -t build-artifacts-container-cross-aarch64 .
```

## Building the admin-cli
The `admin-cli` build does not produce a container. It produces a binary:

`$REPO_ROOT/target/release/carbide-admin-cli`

```
BUILD_CONTAINER_X86_URL="nico-buildcontainer-x86_64" cargo make build-cli
```

### Building the DPU BFB

The BFB build automatically pulls the HBN container from `nvcr.io`. You must
authenticate with NGC before building:

```sh
docker login nvcr.io -u '$oauthtoken' -p <NGC_API_KEY>
```

```sh
cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-bfb-sa

docker build --build-arg "CONTAINER_RUNTIME_AARCH64=alpine:latest" -t boot-artifacts-aarch64 -f dev/docker/Dockerfile.release-artifacts-aarch64 .
```

**NOTE**: The `CONTAINER_RUNTIME_AARCH64=alpine:latest` build argument must be included. The aarch64 binaries are bundled into an x86 container.

## Building REST Containers

The REST components (cloud-api, cloud-workflow, site-manager, site-agent,
db migrations, cert-manager) are built from the
[ncx-infra-controller-rest](https://github.com/NVIDIA/ncx-infra-controller-rest) repository.

```sh
cd ncx-infra-controller-rest
make docker-build IMAGE_REGISTRY=<your-registry.example.com/carbide> IMAGE_TAG=<your-version-tag>
```

### REST Image Summary

| Image | Purpose |
|-------|---------|
| `carbide-rest-api` | REST API server (port 8388) |
| `carbide-rest-workflow` | Temporal workflow worker |
| `carbide-rest-site-manager` | Site management and registry service |
| `carbide-rest-site-agent` | On-site Temporal agent |
| `carbide-rest-db` | Database migration job (runs once per upgrade) |
| `carbide-rest-cert-manager` | PKI certificate manager |
| `carbide-rla` | Rack Level Abstraction service |
| `carbide-psm` | Power Shelf Manager service |
| `carbide-nsm` | NVSwitch Manager service |

## Next Steps

After building all images, you will need to tag them and push them to your private registry.
Refer to the [Tagging and Pushing Containers](pushing_containers.md) section for more details.
