# Carbide - Bare Metal Provisioning

![pipeline status](https://gitlab-master.nvidia.com/aforgue/carbide/badges/trunk/pipeline.svg)

## Introduction

Carbide is a bare metal provisioning system used to manage the lifecycle of bare metal machines.

Please see [The Book](https://nvmetal.gitlab-master-pages.nvidia.com/carbide/index.html) for more detail about roadmap & architecture.

Discussion happens on #ngc-metal slack channel.

## Setting up development environments

### Building using docker

```
   docker run  --volume (pwd):/code -e "RUST_BACKTRACE=1" --workdir /code -it carbide-build cargo build
```

### Pre-reqs
  * direnv
  * Kea
  * Rust
  * Postgresql
  * Vagrant
  * boost-libs
  * gnu-c++

### Postgresql

1. ```sudo -iu postgres```
2. ```initdb --locale=en_US.UTF-8 -E UTF8 -D /var/lib/postgres/data```
3. ```createuser --interactive carbide_development (answer yes to super user)```
4. ```createdb carbide_development```
5. ```cargo run --bin carbide-api migrate```

### Kea
1. Install Kea from package manager or compile from source
2.```cp dev/kea-dhcp4.conf.example dev/kea-dhcp4.conf```
  *Make sure to change the listen interface to reflect your system.*


### Clients
1. Install ```edk2-omvf``` on host. This provides the UEFI files needed

```
   sudo qemu-system-x86_64 -boot n -nographic -serial mon:stdio -cpu host \
   -accel kvm -device virtio-serial-pci -display none \
   -netdev bridge,id=carbidevm,br=carbide0 \
   -device virtio-net-pci,netdev=carbidevm \
   -bios /usr/share/ovmf/OVMF.fd
```

You might need to modify or create /etc/qemu/bridge.conf and add ```allow <bridgename>```

```
grpcurl -d '{"name":"test", "subdomain": "test.com", "prefix_ipv4": "172.20.0.0/24", "prefix_ipv6": "::1/128", "mtu": 1490, "reserve_first_ipv4": 0, "reserve_first_ipv6": 0, "gateway_ipv4": "172.20.0.1" }' -plaintext 127.0.0.1:1079 metal.v0.Metal/CreateNetworkSegment
```

### Setting bridge interface
1. cp 'dev/vagrant/env.example dev/vagrant/.env'
2. Change BRIDGE_INTERFACE to your HOST interface 

##### Still WIP 
