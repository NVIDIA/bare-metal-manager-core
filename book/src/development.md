# Development
We aim to keep the development environment as self-contained and automated as
possible.  Each time we on-board new staff we want to enshrine more of each
development cluster bring up into tooling instead of institutional knowledge.
To that end, we are using docker compose to instantiate a development
environment.

There are preset environment variables that are used throughout the repo.  `${REPO_ROOT}` is used to represent the top of the forge repo tree.

For a list  env vars we predefine look at
`${REPO_ROOT}/.envrc`

## Codebase overview
api - forge primary entrpoint for GRPC API calls. This component receives all the  GRPC calls

book/ - architecture of forge book.  aka "the book"

dev/ - a catch all directory for things that are not code related but are used
to support forge.  e.g. Dockerfiles, kubernetes yaml, etc.

dhcp/ - kea dhcp plugin.  Forge uses ISC Kea for a dhcp event loop.  This code
intercepts DHCPDISCOVERs from dhcp-relays and passes the info to carbide-api

dns/  - provides DNS resolution for assets in forge databse

ipmi/ - a rust FII library around FreeIPMI.  This is used for issuing IPMI
commands to machines

pxe/ - forge-pxe is a web service which provides iPXE and cloud-init data to
machines

rpc/ - protobuf definitions and a rust library which handles marshalling
data from/to GRPC to native rust types

vendor/ - external libraries

vpc/ - local copy of forge-vpc code. Used when building local containers

## Local environment prep

1.  Install rust by following directions [here](https://www.rust-lang.org/tools/install)
2. Install additional cargo utilities

    ```cargo install cargo-watch cargo-make```
3. Install docker following these [directions](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)
4. Install docker-compose using your system package manager

    Arch - ```sudo pacman -S docker-compose```

    Debian - ```sudo apt-get install docker-compose```

    Fedora - ```sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin```

5. Install [KinD](https://kind.sigs.k8s.io/docs/user/quick-start#installing-from-release-binaries)
6. Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
7. Install ISC kea using your system package manager   
    
    Arch - ```sudo pacman -S kea```
    
    Debian - ```sudo apt-get install isc-kea-dhcp4-server isc-kea-dev```

    Fedora - ```sudo dnf install -y kea kea-devel dea-libs``` 

8. You can install PostgresSql locally, but it might be easier to start a docker container when you need to. This is especially useful when running `cargo test` manually.    
    ```docker run -e POSTGRES_PASSWORD="admin" -p "5432:5432" postgres:14.1-alpine```
    
    a. Postgresql CLI utilities should be installed locally
    
    Arch - ```sudo pacman -S postgresql-client```

    Debian - ```sudo apt-get install postgresql-client```

    Fedora - ```sudo dnf install -y postgres```

9. Install qemu and ovmf firmware for starting VM's to simulate PXE clients

     Arch - ```sudo pacman -S qemu edk2-omvf```

     Debian - ```apt-get install qemu ovmf```

     Fedora - ```sudo dnf -y install bridge-utils libvirt virt-install qemu-kvm```

10. Install `direnv` using your package manager. 
    
    Arch - ```sudo pacman -S direnv```
    
    Debian - ```sudo apt-get install direnv```

    Fedora - ```sudo dnf install -y direnv```

11. Install golang using whatever method is most convient for you.  `forge-vpc` (which is in a subtree of the `forge-provisioner` repo uses golang)
12. Because forge-api uses only GRPC, you will need to install some GRPC based client utilities for interacting with the API `evans` and `grpccurl` are primary two.
13. Install 'jq' from system package manager

    Arch - ```sudo pacman -S jq```

    Debian - ```sudo apt-get install jq```

    Fedora - ```sudo dnf install -y jq```


## IDE

Recommended IDE for Rust development in the Carbide project is CLion, IntelliJ works as well but includes a lot of extra components that you don't need.  There are plenty 
of options (VS Code, NeoVim etc), but CLion/IntelliJ is widely used.

One thing to note if regardless of what IDE you choose.. if you're running on Linux DO NOT USE Snap or Flatpak versions of the software packages.  These builds inroduce a number 
of complications in the C lib linking between the IDE and your system and frankly it's not worth fighting.  

## Running Unit Tests

To quickly set up your environment to run unit tests, you'll need an initialized PSQL service locally on your system to connect to.  The docker-compose workflow 
handles this for you, but if you're just trying to set up a simple env to run unit tests run the following:

```docker run --rm -di -e POSTGRES_PASSWORD="admin" -p "5432:5432" --name pgdev postgres:14.1-alpine```

Then init the database:

```cd dev/terraform; docker run -v ${PWD}:/junk --rm hashicorp/terraform -chdir=/junk init```

Now you should be able to run:

```cargo test```

## Workflows

[Docker workflow](docker/development.md)

[Kubernetes workflow](kubernetes/development.md) (STILL WIP but functional)

[iPXE and bootable artifacts](bootable_artifacts.md)
