# Site Reference Architecture 

This page provides guidelines for hardware and configuration for NVIDIA Bare Metal Manager (BMM) managed sites.

## Host Hardware Requirements

The section provides a hardware baseline for the two kinds of hosts, the site controller and compute systems.

The site controller and compute systems must be qualified for one dual-port NVIDIA Bluefield DPU with 2 x 200 Gb network interfaces and a 1 Gb network interface for the BMC. The BlueField-3 B3220 P-Series DPU is suitable (200GbE/NDR200 dual-port QSFP112 Network Adaptor (900-9D3B6-00CV-AA0)). Other network interface controllers on the machine are automatically disabled during site software installation.

### Site Controller Requirements

* **Server class**: Any major OEM Gen5 server (e.g. Dell R760-class)
* **Number of servers**: 3 or 5
* **Server configuration**:
  * **CPU**: 2× modern x86_64 sockets (Intel Xeon/AMD EPYC), 24 or greater cores per socket
  * **Memory**: 256 GiB RAM (minimum), 512 GiB RAM (recommended)
  * **Local storage**: 4Tb or greater capacity on NVMe SSDs
    * **OS**: 200–500 GiB (UEFI + Secure Boot)
    * **K8s data**: 1 or more TiB NVMe dedicated to container runtime, Kubelet, and logs
    * **Secure Erase**: All local storage drives should support Secure Erase.
  * **Networking**: 1–2x 25/100 GbE ports (dual‑homed or single‑homed) for the site-controller host
  * **Out‑of‑band**: BMC/iDRAC/iLO/XClarity (DHCP or statically addressed)
* **Operating system**:
  * **Ubuntu**: 24.04 LTS, kernel 6.8+
  * **Swap**: Disabled (or very small), NUMA enabled, virtualization/IOMMU enabled
  * **TPM**: The TPM 2.0 module must be present on the server and enabled in BIOS/UEFI

### Compute System Requirements

* **Server class**: An [NVIDIA-certified system](https://docs.nvidia.com/ngc/ngc-deploy-on-premises/nvidia-certified-systems/index.html), data center classification
* **Server Configuration**:
  * **GPU**: NVIDIA GB200/GB300 or newer
  * **Local storage**: NVMe drives that support the following:
    * Secure Erase
    * Firmware update must be possible only with signed firmware images.
    * Rollback to previous firmware version must not be possible.
* **Operating System**:
  * **TPM**: TPM 2.0 and Secure Boot support
* **UEFI**: UEFI and host BMC should support the ability to prevent in-band host control
* **Chassis BMC**: Host BMC should provide the following features over Redfish:
  * Power control
  * Setting boot order
  * UEFI control for enabling and disabling secure boot
  * IPv6 capability
  * Firmware update support
  * Serial-over-LAN capability

**Note**: BMM does not require any cabling or communication between the DPU and the host.

## Kubernetes and Runtime

The following versions indicate the tested baseline for the BMM site controller.

* **Kubernetes**: v1.30.x (tested with 1.30.4)
* **CRI**: containerd 1.7.x (tested with 1.7.1)
* **CNI**: Calico backend or equivalent (VXLAN or BGP; choose per network policy/MTU needs)
* **Control-plane footprint**: 3-node minimum for HA; 5-node control plane recommended for large GB200-class sites (e.g. YTL deployment)
* **Time sync**: chrony or equivalent, synced to enterprise NTP
* **Logging/metrics**: Ship system and pod logs off‑host (e.g. to your centralized stack). All logs are collected and shipped using `otel-collector-contrib `(Both Site controller and DPU). All Metrics are scraped and shipped using Prometheus (Both Site controller and DPU).

## Networking Best Practices

### DPUs on Site Controller (Optional)

* DPUs on site controller nodes are optional and site-owned.
* If DPUs are installed, ensure you order the correct DPU power cable from the server vendor.
* For BF3 DPUs, verify link speed and optics: BF3 can run at 200 Gb, so match server/DPU ports to the correct 200 Gb-capable optics, fiber, or DACs.
* For managed hosts where NVIDIA DPUs provide the primary data-plane connectivity, we generally do not add extra ConnectX NICs; a basic onboard NIC for management is sufficient.

### Single Uplink, Logical Separation

Use one physical NIC carrying the following:

* **Mgmt VLAN**: host/SSH/apt/pkg access
* **K8s node traffic**: API server, Kubelet
* **Pod/Service traffic**: Overlay or routed

### Dual-homed Uplink (Reference Design)

This design requires the DPU to be in DPU mode in site controllers.

* The site controller typically uses a single DPU/NIC with two uplinks, each cabled to a different ToR switch participating in BGP unnumbered.
* Both links carry management and Kubernetes traffic; isolation is done via VLANs/VRFs and policy, not by dedicating one NIC to mgmt and one to the data plane.

## General Guidance

* **IP addressing**: The site owner supplies their subnets/VLANs--do not hardcode the default BMM subnets.
* **MTU**: Use 1500 for overlays (VXLAN/Geneve). Use 9000 only if the underlay supports it end‑to‑end.
* **DNS**: Enterprise resolvers; NodeLocal DNS cache is optional.
* **Gateway/routing**: Static or routed (BGP) per site standards--no dependency on BMM routes.
* **Bonding/LACP**: Optional for NIC redundancy; otherwise, you can use simple active/standby.
* **Firewalling**: Allow Kubernetes control-plane and node ports per the chosen CNI, as well as SSH access from a secure management network or jumpbox. Block everything else by default.

## IP Address Pools Required

### Control plane Management Network

* **Number of IPs required per node**:
  * With DPU: 3 (host BMC + DPU ARM OS + DPU BMC)
  * Without DPU: 1(host BMC)

* This is the management network for site controller nodes.
* IP address allocation in this network must be managed by the parent datacenter via DHCP. 
* This network covers the host BMC, plus DPU management (ARM OS and DPU BMC) where DPUs are present.

### Control-Plane Network

**Addressing per site controller node**:
  * When DPUs are used, one `/31` between the DPU and host. 
  * If DPUs are not used, each node requires one IP address.

* Each SC node uses a `/31` point-to-point subnet between the SC OS and the DPU PF representor
* The IPs are allocated statically at the time the OS is installed (and the DPU is configured if present)

### Control Plane Service IP Pool

Typically, this is a `/27` pool.

This pool is required for the services running on the control plane cluster.

### Management Network(s) for Managed Hosts

* **Number of IPs per host**: 1 (host BMC) + 2 × the number of DPUs (DPU ARM OS + DPU BMC per DPU)

* The IP allocation in this network is managed by BMM. 
* The allocation can be split into multiple pools. 
* These subnets must be configured on the out-of-band connected switches, with a DHCP relay configuration pointing to the BMM DHCP service BMM must be informed about them.

### DPU Loopback Pool

* **Number of IPs required per DPU**: 1

* This is the DPU loopback address used during DPU networking.

### BMM Managed Admin Network

This is the host IP when there’s no tenant using it.

* **Number of IPs required per managed server**: 1

* The pool should be large enough for one usable IP per managed server, plus any required network and broadcast addresses for the subnet(s).

### BMM Managed Tenant Network(s)

* **Number of IPs required per managed host per tenant network**: 2 host IPs (PF + VF), provisioned as one `/31` per interface.
  * For example, if you want to provision for two tenant networks, you should provide two pools, each large enough for all servers. 

* When a managed host is allocated to a tenant, it joins a tenant network.
* There can be multiple tenant networks.
* IP allocations are managed by BMM.
* We use `/31` point-to-point subnets per interface; for example, a host with 1 DPU using the PF and one VF consumes 2 × `/31` subnets per tenant network (one `/31` for each interface).

### Switch Configuration

The following is a minimum configuration for switches.

* Connect TOR ports to the site controller (or its DPU). These ports*must* be configured for BGP unnumbered sessions, similar to the configuration used for managed-host DPUs (when in use).
* Enable LACP in sending and receiving mode.
* BGP route maps setup to accept delegated routes from the networking provider
* Enable the EVPN address family.
* Switches *should* accept dual-stacked IPv4 + EVPN sessions from the site controllers.
* Site controllers export their service VIPs with a dedicated EVPN route-target that all managed-host DPUs import.
* Site controllers import EVPN route-targets for the following:
  * All internal tenant networks
  * All external tenant networks
  * Any additional route-targets required for service connectivity (for example, a default route to the Internet or connectivity to a secure management network).


## Storage Layout for K8s (only what we need)

Storage layout for the site controller should keep the OS clean and isolate the container/Kubelet I/O.

* Mount **1.7 Tb on `/` (root)** on NVMe **OS disk** (ext4 or xfs)
  * Usage is typically ~ 200–500 GiB
* Mount **/var/lib/containerd** and **/var/lib/kubelet** on a **separate NVMe data disk** (≥ 1 TiB)
  * Format ext4/xfs; mount with noatime; consider a dedicated `/var/log` if there is heavy logging.
* Use **persistent app storage**, such as SAN/NAS or an add‑on (e.g. Rook‑Ceph), if required by workloads. This is not required for the BMM controller itself.

## Security and Platform Settings

The following are recommended settings for the site controller:

* Enable **UEFI + Secure Boot** (with signed kernel/modules).
* Enable **VT‑x/AMD‑V + IOMMU** in BIOS/UEFI.
* Enable **SR‑IOV** (if using NIC VFs), otherwise leave off.
* Lock **NTP** to enterprise sources; enable clock drift alarms.
