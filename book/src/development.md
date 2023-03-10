# Development

We aim to keep the development environment as self-contained and automated as
possible. Each time we onboard new staff, we want to enshrine more of each
development cluster bring up into tooling instead of institutional knowledge.
To that end, we are using docker-compose to instantiate a development
environment.

## Local environment prep

1. Install rust by following the directions [here](https://www.rust-lang.org/tools/install).
   You will need to use the rustup based installation method to use the same Rust compiler utilized by the CI toolchain.
   You can find the target compiler version in
   [rust-toolchain.toml](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/trunk/rust-toolchain.toml).
   If rustup is installed, you can switch toolchain versions using `rustup toolchain`.

   Make sure you have a C++ compiler:

   Arch - `sudo pacman -S base-devel`

   Debian - `sudo apt-get -y install build-essential libudev-dev`

   Fedora - `sudo dnf -y install gcc-c++ systemd-devel` (systemd-devel needed for libudev-devel)

2. Install additional cargo utilities

   `cargo install cargo-watch cargo-make sccache mdbook mdbook-mermaid`

3. Install docker following these [directions](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository), then add yourself to the docker group: `sudo usermod -aG docker $USER` (otherwise, you must always `sudo` docker`).
4. Install docker-compose using your system package manager

   Arch - `sudo pacman -S docker-compose`

   Debian - `sudo apt-get install -y docker-compose`

   Fedora - `sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-compose`

5. Install ISC kea using your system package manager
   Arch - `sudo pacman -S kea`

   Debian
    - Install required libraries
        - `sudo apt-get install -y libboost-dev`
        - download libssl1 from [here](http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/) and install `sudo dpkg -i <downloaded-lib>`

   - Add the KEA package source, just [as our build container does](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/243203db10f883376c933ed57b6f43a3861c4752/dev/docker/Dockerfile.build-container#L14-15)
     ```
     sudo cp dev/docker/isc-kea-2-0.gpg /etc/apt/trusted.gpg.d/apt.isc-kea-2.0.gpg
     sudo cp dev/docker/isc-kea-2-0.list /etc/apt/sources.list.d/isc-kea-2.0.list
     ```
   - Install kea from source
     ```
     sudo apt-get update && sudo apt-get install -y isc-kea-dhcp4-server isc-kea-dev
     ```

   Fedora - `sudo dnf install -y kea kea-devel kea-libs`

6. You can install PostgreSQL locally, but it might be easier to start a
   docker container when you need to. The docker container is handy when running `cargo test` manually.
   `docker run -e POSTGRES_PASSWORD="admin" -p "5432:5432" postgres:14.1-alpine`

   a. Postgresql CLI utilities should be installed locally

   Arch - `sudo pacman -S postgresql-client`

   Debian - `sudo apt-get install -y postgresql-client`

   Fedora - `sudo dnf install -y postgresql`

7. Install qemu and ovmf firmware for starting VM's to simulate PXE clients

   Arch - `sudo pacman -S qemu edk2-omvf`

   Debian - `apt-get install -y qemu qemu-kvm ovmf`

   Fedora - `sudo dnf -y install bridge-utils libvirt virt-install qemu-kvm`

8. Install `direnv` using your package manager

   It would be best to install `direnv` on your host. `direnv` requires a shell hook to work.  See `man direnv` (after install) for
   more information on setting it up.  Once you clone the `carbide` repo, you need to run `direnv allow` the first time you cd into your local copy.
   Running `direnv allow` exports the necessary environmental variables while in the repo and cleans up when not in the repo.

   There are preset environment variables that are used throughout the repo. `${REPO_ROOT}` represents the top of the forge repo tree.

   For a list environment variables, we predefined look in:
   `${REPO_ROOT}/.envrc`

   Arch - `sudo pacman -S direnv`

   Debian - `sudo apt-get install -y direnv`

   Fedora - `sudo dnf install -y direnv`

9. Install golang using whatever method is most convenient for you. `forge-vpc` (which is in a subtree of the `forge-provisioner` repo uses golang)

10. Install GRPC client `grpcurl`.

    Arch - `sudo pacman -S grpcurl`

    Debian/Ubuntu/Others - [Get latest release from github](https://github.com/fullstorydev/grpcurl/releases)

    Fedora - `sudo dnf install grpcurl`

11. Additionally, `prost-build` needs access to the protobuf compiler to parse proto files (it doesn't implement its own parser).

    Arch - `sudo pacman -S protobuf`

    Debian - `sudo apt-get install -y protobuf-compiler`

    Fedora - `sudo dnf install -y protobuf protobuf-devel`

12. Install `jq` from system package manager

    Arch - `sudo pacman -S jq`

    Debian - `sudo apt-get install -y jq`

    Fedora - `sudo dnf install -y jq`

13. Install `mkosi` and `debootstrap` from system package manager

    Debian - `sudo apt-get install -y mkosi debootstrap`

    Fedora - `sudo dnf install -y mkosi debootstrap`

14. Install `liblzma-dev` from system package manager

    Debian - `sudo apt-get install -y liblzma-dev`

    Fedora - `sudo dnf install -y xz-devel`

15. Install `swtpm` and `swtpm-tools` from system package manager

    Debian - `sudo apt-get install -y swtpm swtpm-tools`

    Fedora - `sudo dnf install -y swtpm swtpm-tools`

16. Install `cmake` from the system package manager:

    Debian - `sudo apt-get install -y cmake`

    Fedora - `sudo dnf install -y cmake`

17. Build the `build-container` locally

    `cargo make build-x86-build-container`

18. Build the book locally

    `cargo make book`

    Then bookmark `file:///$REPO_ROOT/public/index.html`.

## Checking your setup / Running Unit Tests

To quickly set up your environment to run unit tests, you'll need an initialized PSQL service locally on your system. The docker-compose workflow
handles this for you, but if you're trying to set up a simple env to run unit tests run the following.

Start docker daemon:

`sudo systemctl start docker`

Start database container:

`docker run --rm -di -e POSTGRES_PASSWORD="admin" -p "5432:5432" --name pgdev postgres:14.1-alpine`

Init the database:

`cd dev/terraform; docker run -v ${PWD}:/junk --rm hashicorp/terraform -chdir=/junk init`

Test!

`cargo test`

If the tests don't pass ask in Slack #swngc-forge-dev.

Cleanup, otherwise docker-compose won't work later:

`docker ps; docker stop <container ID>`

## IDE

Recommended IDE for Rust development in the Carbide project is CLion, IntelliJ works as well but includes a lot of extra components that you don't need. There are plenty
of options (VS Code, NeoVim etc), but CLion/IntelliJ is widely used.

One thing to note regardless of what IDE you choose: if you're running on Linux DO NOT USE Snap or Flatpak versions of the software packages. These builds introduce a number
of complications in the C lib linking between the IDE and your system and frankly it's not worth fighting.

## Next steps

Setup a complete local environment with docker-compose:

- [Docker workflow](docker/development.md)

Setup a QEMU host for your docker-compose services to manager:

1. [Build iPXE and bootable artifacts image](bootable_artifacts.md)
1. [Start QEMU server](vm_pxe_client.html)
