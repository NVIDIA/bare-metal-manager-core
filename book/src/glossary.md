# Glossary

### BGP (Border Gateway Protocol)

https://en.wikipedia.org/wiki/Border_Gateway_Protocol

Border Gateway Protocol (BGP) is a standardized exterior gateway protocol designed to exchange routing and reachability information among autonomous systems (AS) on the Internet.

### Cloud-Init

https://cloudinit.readthedocs.io/en/latest/

Cloud-init is the industry standard multi-distribution method for cross-platform cloud instance initialization. During boot, cloud-init identifies the cloud it is running on and initializes the system accordingly. Cloud instances will automatically be provisioned during first boot with networking, storage, ssh keys, packages and various other system aspects already configured.

Cloud-init is used by Forge to install components that are required on top of the base OS image:
- DPUs use a Forge provided cloud-init file to install Forge related components
  on top of the base DPU image that is provided by the NVIDIA networking group.
- Customers/tenants can provide a custom cloud-init will do the work of automating installation for customer OS's

### CRD (Kubernetes Custom Resources)

### DHCP (Dynamic Host Configuration Protocol)

https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol (IP) networks for automatically assigning IP addresses and other communication parameters to devices connected to the network using a client–server architecture.

Within Forge, both DPUs and Hosts are using DHCP request to resolve their IP. The Forge infrastructure responds to those DHCP requests, an provides a response based on known information about the host.

### DNS (Domain Name System)

https://en.wikipedia.org/wiki/Domain_Name_System

DNS is a protocol that is used to resolve the internet addresses (IPs)
of services based on a domain name.

### DPU

DPU - A Mellanox BlueField 2 (or 3) network interface card.

https://www.nvidia.com/en-us/networking/products/data-processing-unit/

An list with available SKUs for the card can be found [here](https://nvidia-my.sharepoint.com/:x:/r/personal/tal_nvidia_com/_layouts/15/doc2.aspx?sourcedoc=%7B456F2AFC-D58F-4FF9-892D-07615C4D39D7%7D&file=BlueField%20OPN%20Scheme.xlsx)

### FleetCommand

### HBN (Host Based Networking)

A feature of Cumulus Linux and the DPU cards its running on to configure network routing.

https://docs.nvidia.com/doca/sdk/pdf/doca-hbn-service.pdf

### IPMI (Intelligent Platform Management Interface)

https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface

The Intelligent Platform Management Interface (IPMI) is a set of computer interface specifications for an autonomous computer subsystem that provides management and monitoring capabilities independently of the host system's CPU, firmware (BIOS or UEFI) and operating system. IPMI defines a set of interfaces used by system administrators for out-of-band management of computer systems and monitoring of their operation. For example, IPMI provides a way to manage a computer that may be powered off or otherwise unresponsive by using a network connection to the hardware rather than to an operating system or login shell. Another use case may be installing a custom operating system remotely.

### iPXE

https://en.wikipedia.org/wiki/IPXE

iPXE is an open-source implementation of the [Preboot eXecution Environment (PXE)](glossary.md#PXE) client software and bootloader. It can be used to enable computers without built-in PXE capability to boot from the network, or to provide additional features beyond what built-in PXE provides.

### Kubernetes

### Leaf

In the Forge project, we call "Leaf" the device that the host (which we to make available for tenants) plugs into.
This is typically a DPU that will make the overlay network available
to the tenant. In future iterations of the Forge project, the Leaf might be a specialized switch instead of a DPU. 

### POD

### PXE

In computing, the Preboot eXecution Environment, PXE specification describes a standardized client–server environment that boots a software assembly, retrieved from a network, on PXE-enabled clients.

In Forge, DPUs and Hosts are using PXE after startup to install both the
Forge specific software images as well as the images that the tenant
wants to run.
