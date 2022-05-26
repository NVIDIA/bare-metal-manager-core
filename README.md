# Carbide - Bare Metal Provisioning
![pipeline status](https://gitlab-master.nvidia.com/aforgue/carbide/badges/trunk/pipeline.svg)
## Introduction

Carbide is a bare metal provisioning system used to manage the lifecycle of
bare metal machines.

Please see [The Book](https://nvmetal.gitlab-master-pages.nvidia.com/carbide/index.html) for more detail about roadmap & architecture.

Discussion happens on #ngc-metal slack channel.

## Setting up development environments

We aim to keep the development environment as self-contained and automated as
possible.  Each time we on-board new staff we want to enshrine more of each
development cluster bring up into tooling instead of institutional knowledge.
To that end, we are using docker compose to instantiate a development
environment.

[The docker compose configuration file](docker-compose.yml) contains all of the
software in the control plane in order to make requests to a working Carbide
installation.

The docker-compose configuration starts an environment that looks generally 
like this:

```mermaid
flowchart TD 
    subgraph Docker-Compose
        gw(("Envoy"))
        dhcp["Carbide DHCP"]
        api["Carbide gRPC"]
        pxe["Carbide PXE"]
        pg["PostgreSQL"]
        vault["Hashicorp Vault"]
        terraform["Hashicorp Terraform"]
    end

    subgraph Volumes
        data[("PostgreSQL Data")]
    end

    gw --> api
    gw --> pxe
    api --> pg
    pxe --> api
    pg ==> data
    dhcp --> api

    subgraph External
        client_dhcp["DHCP Client"]
        client_api["API Client"]
        client_pxe["PXE Client"]
    end

    client_pxe -->|port 8080| gw
    client_api -->|port 80| gw
    client_dhcp -->|port 67| dhcp

    terraform -..->|provisioner| vault
```

The container used to run components is specified by [the default
Dockerfile](Dockerfile).  This contains the prereqs to run the components and
where the build actually happens.  The containers run ```cargo watch``` in
order to recompile on changes.

(NOTE: this messes with ```rust-analyzer``` and needs someone to fix it)


### QEMU
QEMU and UEFI firmware are required to PXE boot a VM using Carbide

Arch - `pacman -S qemu edk2-ovmf`
Ubuntu - `apt-get install qemu ovmf`

You might need to modify or create `/etc/qemu/bridge.conf` and add `allow carbide0`

`cargo install cargo-make`

Build a container for running local development

```
cargo make runtime-container
```

### docker

We use docker-compose to spin up a local carbide development environment

Arch - `pacman -S docker-compose`
Ubuntu - `apt-get install docker-compose`

Before you can start the carbide development environment you must `init` terraform
to create a terraform state file which we do not checked into VCS.

In `dev/terraform` directory, run:

```
   docker run -v ${PWD}:/junk --rm hashicorp/terraform -chdir=/junk init
```

When you down your docker compose environment, sometimes stale data can persist on volumes. 
Be sure to use the `-v` flag to remove all the volumes so you do not end up with "odd" behavior

```
docker-compose down -v
docker-compose up
```

### Bootstrapping Carbide
Create a new VPC, Domain and networksegment.
```
vpc=$(grpcurl -d '{"name":"test_vpc"}' -plaintext 127.0.0.1:80 metal.v0.Metal/CreateVpc | jq ".id.value" | tr -d '"')

domain=$(grpcurl -d '{"name":"forge.local"}' -plaintext 127.0.0.1:80 metal.v0.Metal/CreateDomain | jq ".id.value" | tr -d '"')

grpcurl -d "{\"name\":\"test\", \"mtu\": 1490, \"prefixes\":[{\"prefix\":\"172.20.0.0/24\",\"gateway\":\"172.20.0.1\",\"reserve_first\":21}, {\"prefix\":\"::1/128\", \"reserve_first\":0}], \"subdomain_id\": { \"value\":\"$domain\"}, \"vpc_id\": { \"value\": \"$vpc\"}}" -plaintext 127.0.0.1:80 metal.v0.Metal/CreateNetworkSegment
```

```
INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, domain_id, hostname,primary_interface) VALUES ('<machine_id>', '<segment_id>', 'de:af:de:ad:be:ed',  '<domain_id>','myhost', true);
```

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

### PXE Client

You can start qemu with or without graphics. If your LiveOS is a graphical OS, remove the `-nographic` and `-display none` to have an actual window pop up.

```
sudo qemu-system-x86_64 -boot n -nographic -display none \
  -serial mon:stdio -cpu host \
  -accel kvm -device virtio-serial-pci \
  -netdev bridge,id=carbidevm,br=carbide0 \
  -device virtio-net-pci,netdev=carbidevm \
  -bios /usr/share/ovmf/OVMF.fd -m 4096
```

This should boot you into the prexec image, and its user is `root` and password is specified in the mkosi.default file.

In order to exit use `ctrl-a x` 

**Note**: As of this commit, there is a bug that will cause the ipxe dhcp to fail the first time it is run. Wait for it to fail,
and in the EFI Shell just type `reset` and it will restart the whole pxe process and it will run the ipxe image properly the second time.
See https://jirasw.nvidia.com/browse/FORGE-243 for more information.


While not needed for PXE, it is sometimes helpful to seed DB entries 
for debugging SQL queries: 

```
INSERT INTO machines DEFAULT VALUES;


INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, domain_id, hostname,primary_interface) VALUES ('<machine uuid>', '<segment uuid>', 'de:af:de:ad:be:ed', '<domain uuid>', 'myhost', true);


INSERT INTO machine_interface_addresses (inteface_id, address) VALUES (<interface_id>, <address>);
```
## SJC4 Lab Environments
### Required access groups
In order to reach the any of IP's listed you will need to be a member of 
the `ngc-automation` and `sagan` ssh groups. Without this ssh access you cannot
access the jump hosts.

You must first install [nvinit](https://confluence.nvidia.com/display/COS/Security+Engineering+Home#SecurityEngineeringHome-CertificateBasedSSHAccessforNGCHosts) and Hashicorp vault

SSH group membership:

First is `sagan`.  Make a [dlrequest](https://dlrequest/GroupID/Groups/Properties?identity=M2UwMzM1NGI0M2Q2NDFkZWIyZTUwZjA1Zjk4YmQxMmV8Z3JvdXA=) Click Join -> Join perpetually

Second group is `ngc-automation`, open a Jira using [this](https://jirasw.nvidia.com/browse/NGCSEC-1183) as a template

When you have been added to one of the groups, you will need to sign-in to vault

```
vault login -method=ldap username=<your AD username> -passcode=<passcode from duo>  
```

You will know when you are a member a group based on the policies 
returned from `vault login` (example below where you are a member of `sagan` and `ngc-automation`)

```
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  XXXXXXXXXXX
token_accessor         XXXXXXXXXXX
token_duration         1h
token_renewable        true
token_policies         ["default" "jwt-nvidia-policy" "ngc-devops-service-accounts-policy" "ngc-user-policy" "sagan-policy"]
identity_policies      ["jwt-nvidia-policy"]
policies               ["default" "jwt-nvidia-policy" "ngc-devops-service-accounts-policy" "ngc-user-policy" "sagan-policy"]
token_meta_username    <your AD login>
```

Once authenticated to vault, you use nvinit to request additional principals
Before running the commands below make sure to have `ssh-agent` running.  
```
eval $(ssh-agent)
ssh-add -D
```

```
nvinit ssh -user <AD username> -principals "<AD username>,bouncer" -passcode <DUO passcode>
nvinit ssh -user <AD username> -vault-role sshca-usercert/issue/sagan
nvinit ssh -user <AD username> -vault-role sshca-devopscert/issue/ngc-automation
```

Add the following to your `.ssh/config`. The user depends on which ssh group you use are a member of,
but bouncer should be sufficient for most.

```
Host sjc4jump
  Hostname 24.51.7.3
  Compression yes
  User ngc-devops
  PubkeyAcceptedKeyTypes=+ssh-rsa-cert-v01@openssh.com  // This is only required if you are running the latest SSH.  OpenSSH deprecated RSA a while ago
```
### Host info
Related Info about Lab hosts:

https://jirasw.nvidia.com/browse/NSVIS-3666
https://docs.google.com/spreadsheets/d/1wbRW8zcw_rx05fgP6ThK288d0W_WRIVe6uErUpqT0Eg/edit?userstoinvite=rdancel@nvidia.com&actionButton=1#gid=2074715696
https://netbox.nvidia.com/dcim/racks/6496/


| hostname   | DPU BMC IP    | DPU OOB IP    | HOST OOB IP   | HOST IP                          | DPU BMC Credentials | DPU OOB Credentials | HOST OOB ILO Creds    | Host OS Creds   |
| ---------- | ------------- | ------------- | ------------- | -------------------------------- | ------------------- | ------------------- | --------------------- | --------------  |
| forge001   | 10.146.38.232 | 10.146.38.229 | 10.146.38.242 | 10.150.51.235 / 10.150.51.236    | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge002   | 10.146.38.231 | 10.146.38.247 | 10.146.38.243 | 10.150.51.242 / 10.150.115.235  | `root:M/uz{HKh@fz6S-%8`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge003   | 10.146.38.241 | 10.146.38.240 | 10.146.38.244 | 10.150.51.230 / 10.150.115.242    | `root:M/uz{HKh@fz6S-%8`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge004   | 10.146.38.235 | 10.146.38.226 | 10.146.38.245 | Dynamic                          | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |
| forge005   | 10.146.38.236 | 10.146.38.225 | 10.146.38.246 | Dynamic                          | `root/0penBmc123`   | `ubuntu:ubuntu`     | `sjc4dcops:sjc4dcops` | `ubuntu:ubuntu` |

### BGP Info

| Device_A_name   | Device_A_Nic | IP Address     | Device_A_Loopback | Device_A_ASN | Peer_IP	Peer  | ASN   |
|-----------------|--------------|----------------|-------------------|--------------|----------------|-------|
| sjc4-d32-nv-01  | dpu_nic0     | 10.150.51.200  | 10.145.0.80       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-01  | dpu_nic1     | 10.150.115.200 | 10.145.0.81       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-nv-02  | dpu_nic0     | 10.150.51.201  | 10.145.0.82       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-02  | dpu_nic1     | 10.150.115.201 | 10.145.0.83       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-nv-03  | dpu_nic0     | 10.150.51.202  | 10.145.0.84       | 65280        | 10.150.51.193  | 65240 |
| sjc4-d32-nv-03  | dpu_nic1     | 10.150.115.202 | 10.145.0.85       | 65281        | 10.150.115.193 | 65240 |
| sjc4-d32-cpu-01 | dpu_nic0     | Unnumbered     | Dynamic           | Dynamic      | 10.150.51.193  | 65240 |
| sjc4-d32-cpu-01 | dpu_nic1     | Unnumbered     | Dynamic           | Dynamic      | 10.150.115.193 | 65240 |
| sjc4-d32-cpu-02 | dpu_nic0     | Unnumbered     | Dynamic           | Dynamic       | 10.150.51.193  | 65240 |
| sjc4-d32-cpu-02 | dpu_nic1     | Unnumbered     | Dynamic           | Dynamic        | 10.150.115.193 | 65240 |

Note: **Dynamic** indicates resources are managed by Forge, and Forge allocates these resources from [SJC4 Forge Dev](https://docs.google.com/spreadsheets/d/1wbRW8zcw_rx05fgP6ThK288d0W_WRIVe6uErUpqT0Eg/edit#gid=701174353).

### Reno host info
There is not presently much information other than the DPUs BMCs in Reno. The machines are in unknown state
and the forge discovery image will reset the BMCs. DC Ops may have to set them all to pxe boot though.

Note: .53 is currently not responding as the x86 it was in died, it will come online when new gear arrives

- https://docs.google.com/spreadsheets/d/172XpZFYMAo_Ph98FMflqztnBE5fILUIeWe9b20R2cQE/edit#gid=0
- B17 - https://netbox.nvidia.com/dcim/racks/9953/
- B18 - https://netbox.nvidia.com/dcim/racks/9954/
- B19 - https://netbox.nvidia.com/dcim/racks/9955/

| BMC IP | BMC Eth | OOB IP | OOB Eth | Serial |
| ---------- | ------------- | ------------- | ------------- | ------------------- | 
| 10.180.222.11 |	10:70:fd:18:0f:3e	| 10.180.222.18 |	10:70:fd:18:0f:4a |	MT2203X26565 |
| 10.180.222.15 |	10:70:fd:18:10:5e	| 10.180.222.13 |	10:70:fd:18:10:6a |	MT2203X26583 |
| 10.180.222.16 |	10:70:fd:18:0f:ee	| 10.180.222.35 |	10:70:fd:18:0f:fa |	MT2203X26576 |
| 10.180.222.17 |	10:70:fd:18:0f:6e |	10.180.222.43 |	10:70:fd:18:0f:7a |	MT2203X26568 |
| 10.180.222.19 |	10:70:fd:18:0f:0e |	10.180.222.25 |	10:70:fd:18:0f:1a |	MT2203X26562 |
| 10.180.222.20 |	10:70:fd:18:0f:8e |	10.180.222.45 |	10:70:fd:18:0f:9a |	MT2203X26570 |
| 10.180.222.21 |	10:70:fd:18:0f:2e |	10.180.222.14 |	10:70:fd:18:0f:3a |	MT2203X26564 |
| 10.180.222.23 |	10:70:fd:18:0f:fe |	10.180.222.46 |	10:70:fd:18:10:0a |	MT2203X26577 |
| 10.180.222.26 |	10:70:fd:18:0f:ce |	10.180.222.47 |	10:70:fd:18:0f:da |	MT2203X26574 |
| 10.180.222.27 |	10:70:fd:18:0f:5e |	10.180.222.48 |	10:70:fd:18:0f:6a |	MT2203X26567 |
| 10.180.222.28 |	10:70:fd:18:0f:be |	10.180.222.10 |	10:70:fd:18:0f:ca |	MT2203X26573 |
| 10.180.222.29 |	10:70:fd:18:10:6e |	10.180.222.24 |	10:70:fd:18:10:7a |	MT2203X26584 |
| 10.180.222.30 |	10:70:fd:18:10:0e |	10.180.222.31 |	10:70:fd:18:10:1a | MT2203X26578 |
| 10.180.222.33 |	10:70:fd:18:10:3e |	10.180.222.40 |	10:70:fd:18:10:4a	| MT2203X26581 |
| 10.180.222.34 |	10:70:fd:18:0f:ae |	10.180.222.38 |	10:70:fd:18:0f:ba |	MT2203X26572 |
| 10.180.222.36 |	10:70:fd:18:10:2e |	10.180.222.42 |	10:70:fd:18:10:3a | MT2203X26580 |
| 10.180.222.37 |	10:70:fd:18:0f:9e |	10.180.222.39 |	10:70:fd:18:0f:aa |	MT2203X26571 |
| 10.180.222.41 |	10:70:fd:18:10:7e |	10.180.222.49 |	10:70:fd:18:10:8a |	MT2203X26585 |
| 10.180.222.53 |	6a:7c:1a:43:16:64 |	10.180.222.44 |	10:70:fd:18:10:5a |	MT2203X26582 |


### Connecting to DPU
The DPU shares a physical 1GB ethernet connection for both BMC and OOB access.  
This one interface has two different MAC addresses. So, while the physical 
connection is shared the OOB and BMC have unique IP addresses.

The BMC OS is a basic `busybox` shell,  so the available commands are limited.
To connect the BMC, ssh to the IP address listed under `DPU BMC IP` address 
using credentials in the `DPU BMC Credentials` table above.

To then connect to the 'console' of the DPU you use `microcom` on the
console device

```
microcom /dev/rshim0/console

Press enter to bring up login prompt.

use the login credentials in the DPU OOB column to connect

ctrl-x will break out of the connection
```

Another way (and preferred if the OOB interfaces are provisioned) is to ssh
directly to the IP listed in `DPU OOB IP` and use the credentials in the
`DPU OOB Credentials` column. This bypasses the BMC and connects you directly to
the DPU OS.

#### Updating to the latest BFB on a DPU


Download the latest BFB from artifactory - https://urm.nvidia.com/artifactory/list/sw-mlnx-bluefield-generic/Ubuntu20.04/

In order to upgrade the OS you will need to `scp` the BFB file to a specific directory on the DPU.
`scp DOCA_1.3.0_BSP_3.9.0_Ubuntu_20.04-3.20220315.bfb root@bmc_ip:/dev/rshim0/boot` once the file is copied the DPU reboots and completes the install of the new BFB.

Note you will need to request access to the `ngc-automation` or `sagan` ssh group
in order to login to a jump host.



Recent versions of BFB can also contain firmware updates which can need to be applied using `/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl` after that completes
you must power cycle (not reboot) the server.  For HP the "Cold restart" option in iLO works.   

`mlxfwmanager` will tell you the current version of firmware as well as the new version that will become active on power cycle

Open Vswitch is loaded on the DPUs 
`ovs-vsctl` show will show which interfaces are the bridge interfaces

From the ArmOS BMC you can instruct the DPU to restart using 

`echo "SW_RESET 1" > /dev/rshim0/misc`

The DPU Might require the following udev rules to enable auto-negotiation.  You can look if that is already enable

```
echo 'SUBSYSTEM=="net", ACTION=="add", NAME=="p0", RUN+="/sbin/ethtool -s p0 autoneg on"' >> /etc/udev/rules.d/83-net-speed.rules
echo 'SUBSYSTEM=="net", ACTION=="add", NAME=="p1", RUN+="/sbin/ethtool -s p1 autoneg on"' >> /etc/udev/rules.d/83-net-speed.rules
```

```
ethtool p0 | grep -P 'Speed|Auto'
ethtool p1 | grep -P 'Speed|Auto';

Output should look like this assuming it is connecting to a 25G port

	Speed: 25000Mb/s
	Auto-negotiation: on
```

#### Connecting to the Host/X86 OOB Interface
The OOB of the servers in this lab is HP ilo.  In order to connect to the OOB you will
first need to setup ssh port forwarding, as there is no direct access from your workstation

`ssh -D 1080 <login>@<some jump host>`

After that connection is established, open a browser (I am using firefox)
![firefox_proxy](dev/static/firefox_proxy.gif "Firefox")


Once you have configured firefox to use the ssh connection as a SOCKS proxy, you can 
put use the ip address of the host OOB. e.g. `https://<host OOB IP>` and which point
the HP iLO interface should show up and you can login with the credentials shown above.


## Production containers on Quay.io

You must first be a member of the nvidia organization at Quay.io hop
 #swngc-devops

TODO


---

# New or bored
## Still needs documentation

If you're new or bored, feel free to do one of these:

- How to configure libvirt for qemu based PXE booting on EFI
- How to configure DHCP relay to the docker-compose constellation
- Document how to run the Ci/CD tests that gitlab does, locally

## If you see something, say something

If you see possible improvements or doing things that are sub-optimial, but don't have time to fix it, just file a jira and move on.


---
# Local kube setup
Download and install KinD (Kubernetes in docker)
https://kind.sigs.k8s.io/docs/user/quick-start/#installing-from-release-binaries

You will also want to install kubectl (version 1.24+)
https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/

```
cargo make kind
```

If for some reason you need to delete the cluster and start over:
```
kind delete cluster --name forge-local
```
This will spin up a kind cluster, build and upload the carbide image, and apply
all the kubernetes primitives to expose carbide services.

When booting the test VM from your local workstation, use the new bridge that 
KinD created for kubernetes.

To interact with carbide-api use the url `http://127.0.0.1:11079`

To view logs for a particular application, the most straightforward way is to
```
kubectl get pods
kubectl logs <podname> -f 
```

You can also reference pods by labels (metadata -> labels) which are defined 
in podspec or deploymentspec files.

```
kubectl logs -n default -l app=carbide-dhcp -f
```

---

# Legacy / Archival

### Pre-reqs
  * Kea
  * Rust
  * Postgresql
  * boost-libs
  * gnu-c++

### PostgreSQL

You can run PostgreSQL locally if you wish.  We expect your unix username to be
able to create/delete databases for tests, or have a single database to run the
code in.

1. ```sudo -iu postgres```
2. ```initdb --locale=en_US.UTF-8 -E UTF8 -D /var/lib/postgres/data```
3. ```createuser --interactive carbide_development (answer yes to super user)```
4. ```createdb carbide_development```
5. ```cargo run --bin carbide-api migrate```

### Kea

1. Install Kea from package manager or compile from source
2.```cp dev/kea-dhcp4.conf.example dev/kea-dhcp4.conf```
  *Make sure to change the listen interface to reflect your system.*
