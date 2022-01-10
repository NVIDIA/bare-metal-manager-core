# Carbide - Bare Metal Provisioning

![pipeline status](https://gitlab-master.nvidia.com/aforgue/carbide/badges/trunk/pipeline.svg)

## Introduction

Carbide is a bare metal provisioning system used to manage the lifecycle of bare metal machines.

Please see [The Book](https://bcmetal.gitlab-master-pages.nvidia.com/carbide/book/index.html) for more detail about roadmap & architecture.

Discussion happens on #ngc-metal slack channel.

## Setting up development environments

### Pre-reqs
  * Kea
  * Rust
  * Postgresql
  * Vagrant

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


##### Still WIP 
