# Glossary

### Forge & Carbide

You will see references to the name "Forge" and "Carbide". These were names for internal NVIDIA projects that were the precursors to NVIDIA Bare Metal Manager.  Some of the names lives on in the source and docs but references to these things are being removed over time as we try to break as little code and commands as possible.

### BGP (Border Gateway Protocol)

https://en.wikipedia.org/wiki/Border_Gateway_Protocol

Border Gateway Protocol (BGP) is a standardized exterior gateway protocol designed to exchange routing and reachability information among autonomous systems (AS) on the Internet.

### BMC (Baseboard Management Controller)

Runs the BIOS, controls power on/off of the machine it's responsible for. The **Host** has a BMC, and the **DPU** has a separate BMC. The **Host**'s BMC runs a web server which provides both a web interface to manage BIOS settings, and a [Redfish](https://en.wikipedia.org/wiki/Redfish_(specification)) API. The BMC is how we can programmatically reboot a machine.

### Cloud-Init

https://cloudinit.readthedocs.io/en/latest/

Cloud-init is the industry standard multi-distribution method for cross-platform cloud instance initialization. During boot, cloud-init identifies the cloud it is running on and initializes the system accordingly. Cloud instances will automatically be provisioned during first boot with networking, storage, ssh keys, packages and various other system aspects already configured.

Cloud-init is used by Carbide to install components that are required on top of the base OS image:
- DPUs use a Carbide provided cloud-init file to install Carbide related components
  on top of the base DPU image that is provided by the NVIDIA networking group.
- Customers/tenants can provide a custom cloud-init will do the work of automating installation for customer OS's

### DHCP (Dynamic Host Configuration Protocol)

https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol (IP) networks for automatically assigning IP addresses and other communication parameters to devices connected to the network using a client–server architecture.

Within Carbide, both DPUs and Hosts are using DHCP request to resolve their IP. The Carbide infrastructure responds to those DHCP requests, an provides a response based on known information about the host.

### DNS (Domain Name System)

https://en.wikipedia.org/wiki/Domain_Name_System

DNS is a protocol that is used to resolve the internet addresses (IPs)
of services based on a domain name.

### DPU

DPU - A [Mellanox BlueField 2 (or 3)](https://www.nvidia.com/en-us/networking/products/data-processing-unit/) network interface card. It has an ARM processor and runs a modified Ubuntu. It has its own **BMC**. It can act as a network card and as a disk controller.

### HBN (Host Based Networking)

Software networking switch running in a container on the **DPU**. Manages network routing. Runs [Cumulus Linux](https://www.nvidia.com/en-us/networking/ethernet-switching/cumulus-linux/). Carbide controls it via VPC and `forge-dpu-agent`.

https://docs.nvidia.com/doca/sdk/pdf/doca-hbn-service.pdf

### Host

A **Host** is the computer the way a customer thinks of it, currently with an x86 processor. It is the "bare metal" we are managing. It runs whatever OS the customer puts in it. See also **ManagedHost** and **DPU**.

### Instance

An Instance is a **Host** currently being used by a customer.

### IPMI (Intelligent Platform Management Interface)

https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface

The Intelligent Platform Management Interface (IPMI) is a set of computer interface specifications for an autonomous computer subsystem that provides management and monitoring capabilities independently of the host system's CPU, firmware (BIOS or UEFI) and operating system. IPMI defines a set of interfaces used by system administrators for out-of-band management of computer systems and monitoring of their operation. For example, IPMI provides a way to manage a computer that may be powered off or otherwise unresponsive by using a network connection to the hardware rather than to an operating system or login shell. Another use case may be installing a custom operating system remotely.

### iPXE

https://en.wikipedia.org/wiki/IPXE

iPXE is an open-source implementation of the [Preboot eXecution Environment (PXE)](glossary.md#PXE) client software and bootloader. It can be used to enable computers without built-in PXE capability to boot from the network, or to provide additional features beyond what built-in PXE provides.

### Leaf

In the Carbide project, we call "Leaf" the device that the host (which we to make available for tenants) plugs into.
This is typically a DPU that will make the overlay network available
to the tenant. In future iterations of the Carbide project, the Leaf might be a specialized switch instead of a DPU.

### Machine

Generic term for either a **DPU** or a **Host**. Compare with **ManagedHost**.

### ManagedHost

A **ManagedHost** is a box in a data center. It contains two **Machine**: one **DPU** and one **Host**.

### POD

A Kubernetes thing

### PXE

In computing, the Preboot eXecution Environment, PXE specification describes a standardized client–server environment that boots a software assembly, retrieved from a network, on PXE-enabled clients.

In Carbide, DPUs and Hosts are using PXE after startup to install both the
Carbide specific software images as well as the images that the tenant
wants to run.

### VLAN

A 12-bit ID inserted into an Ethernet frame to identify which virtual network it belongs to. Switches/routers are VLAN aware. The limitations of only have 4096 VLAN IDs means that VXLAN is usually used instead.

In our setup VLAN IDs only exist in the DPU-Host communication, and would be needed if the host was running a Hypervisor. The VLAN ID would identify which virtual machine the Ethernet frame should be delivered to.

See also: [VXLAN](glossary.md#vxlan).

### VNI

Another name for VXLAN ID. See [VXLAN](glossary.md#vxlan).

### VTEP

VXLAN Tunnel EndPoint. See [VXLAN](glossary.md#vxlan).

### VXLAN

[Virtual Extensible LAN](https://en.wikipedia.org/wiki/Virtual_Extensible_LAN). In a data center we often want to pretend that we have multiple networks, but using a single set of cables. A customer will want all their machines to be on a single network, separate from the other customers, but we don't want to run around plugging cables in every time tenants change. The answer to this is virtual networks. An Ethernet packet is wrapped in a VXLAN packet which identifies which virtual network it is part of.

The VXLAN packet is just an 8-byte header, mostly consisting of a 24-bit identifier, known as the VXLAN ID or VNI. The VXLAN wrapping / unwrapping is done by a VTEP. In our case the DPU is the VTEP. The customers' Ethernet frame goes into a VXLAN packet identified by a VXLAN ID or VNI, that goes in a UDP packet which is routed like any other IP packet to its receiving VTEP (in our case usually another DPU), where it gets unwrapped and continues as an Ethernet frame. This allows the data center networking to only route IP packets, and allows the x86 host to believe it got an Ethernet frame from a machine on the same local network.
