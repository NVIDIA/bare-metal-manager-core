# FAQs

This document contains frequently asked questions about NCX Infra Controller (NICo).

**Does NICo install Cumulus Linux onto ethernet switches?**

No, NICo does not install Cumulus Linux onto Ethernet switches.

**Does NICo install UFM?**

No, NICo does not install UFM, it is a dependency. NICo leverages existing UFM deployments for InfiniBand partition management via the UFM API using pkey. 

**Does NICo manage Infiniband switches in standalone mode (i.e. without UFM)?**

No, NICo does not manage Infiniband switches in standalone mode. It requires UFM for InfiniBand partitioning and fabric management. NICo calls UFM APIs to assign partition keys (P_Keys) for isolation.

**Does NICo maintain the database of the tenancy mappings of servers and ports?**

NICo stores the owner of each instance in the form of a `tenant_organization_id` that is passed during instance creation.

![NICo Tenancy Mapping](static/faq_tenency_mappings.png)

**Does NICo speak to NetQ to learn about the network?**

No, the NICo does not speak to NetQ.

**Does NICo install DPU OS?**

Yes, NICo installs the DPU OS, including all DPU firmware (BMC, NIC, UEFI). NICo also deploys HBN, a containerized service that packages the same core networking components (FRR, NVUE) that power Cumulus Linux.

**Does NICo bring up NVLink?**

No, NICo does not bring up NVLink. However, NICo manages NVLink partitions through NMX-M APIs. Plans to manage NVLink switches are being evaluated. 

**Does NICo support NVLink partitioning?**

Yes, NICo supports NVLink partitioning.

**How does NICo maintain tenancy enforcement between Ethernet (N/S), Infiniband (E/W), NVLink (GPU-to-GPU) networks?**

* **Ethernet**: VXLAN with EVPN for VPC creation on DPU
* **E/W Ethernet (Spectrum-X)**: CX-based FW called DPA to do VXLan on CX (as part of future release)
* **Infiniband**: UFM-based partition key (P_Key) assignment
* **NVLink**: NMX-M based partition management

DPUs enforce Ethernet isolation in hardware, UFM enforces IB isolation, and NMX-M enforces NVLink isolation--all coordinated by NICo.

**When NICo is used to maintain tenancy enforcement for Ethernet (N/S), does it require access to make changes to SN switches running Cumulus or are all changes limited to HBN on the DPU?**

Ethernet tenancy enforcement is limited to HBN (Host-Based Networking) on the DPU and does not require NICo to make changes to Spectrum (SN) switches running Cumulus Linux.  NICo expects the switch configuration to provide BGP speakers on the Switches that speak IPv4 Unicast and L2/L3 EVPN address families, and “BGP Unnumbered” (RFC 5549)

**When NICo is used to maintain tenancy enforcement for Ethernet and hosts are presented to customers as bare metal, is OOB isolation of GPU/CPU host BMC managed as well or only the N/S overlay running on DPU?**

NICo configures the host BMC to disable connectivity from within the host to the BMC (e.g. Dell iDrac Lockdown, disabling KCS, etc), and also prevents access from the host (via network) to the BMC of the host. Effectively, the user cannot access the BMC of the bare metal hosts.  The BMC console (Serial console) is accessed by a user through a NICo service called SSH console that does Authentication and Authorization that the user accessing the console is the current owner of the machine.


**Can NICo be used to manage a portion of a cluster?**

NICo requires the N/S and OOB Ethernet DHCP relays pointed to the NICo DHCP service as well as access to UFM and NMX-M for E/W. Additionally, the EVPN topology must be visible to all nodes that are managed by the same cluster. If the DC operator wants to separate EVPN/DHCP into VLANs and VRFs, then you can arbitrarily assign nodes to NICo management or not. NMX-M and UFM are not multi–tenant aware, so there's a possibility of two things configuring NMX-M and UFM from interfering with each other.

**Can NICo be utilized for HGX platforms for host life cycle management?**

Yes, in addition to DGX as well as OEM/ODM CPU-only, Storage, etc nodes.

**Does NICo support installing an OS onto the servers? What OS’s are supported to install on NICo?**

Yes, NICo supports OS installation onto servers through PXE & Image-based. Any OS can be installed via iPXE (http://ipxe.org) that iPXE supports. OS management (patching, configuration, image generation) is the user’s responsibility. 

**What is the way to communicate with NICo? Does it expose an API? Does it have a shell interface?**

NICo exposes an API interface & authentication through JWT tokens or IdP integration (keycloak). There is also an admin-facing CLI & debugging/Engineering UI. 

**Where is NICo run? Is it a container/microservice? Is it a single container or a collection deployed via Helm?**

NICo commonly runs on a Kubernetes cluster (3 or 5 control plane nodes recommended), though there is no requirement to do so. NICo runs as a set of microservices for API, DNS, DHCP, Hardware Monitoring, BMC Console, Rack Management, etc. There is currently no helm chart for NICo deployment; it can be deployed with Kubernetes Kustomize manifests.

**Should I use NICo as my OS installation tool?**

NICo is more than an OS installation tool. It certainly helps with OS provisioning, but it's not the main use case for NICo. Automated Baremetal lifecycle management, network isolation & rack management are its key use cases.  This includes hardware burn-in testing, hardware completeness validation, Measured Boot for Firmware integrity and ongoing automated firmware updates, and out-of-band continuous hardware management.

**Do I need to change the OOB management TOR to configure a separate VLN for the NICo managed hosts and DPU (DPU OOB, Host OOB), with DHCP relay point to NICo DHCP?**

Yes, that's usually how it's done.  Each VLAN (sometimes the whole switch is a VLAN) - or SVI port - needs to have its DHCP relay for the machines and DPUs you wish to manage with NICo pointing to NICo's DHCP server address you setup.

**Do I need to change existing infrastructure if separate VLANs are used?**

No, there is no need to change existing infrastructure if separate VLANs are used.

**With only one RJ45 on BF3, the DPU inband IP addresses allocation is part of DPU loopback allocated by NICo. Does it assume that the same management switch also supports DPU SSH access and that the DPU ssh IP is allocated by NICo and only accessible inside the data center?**

The IP addresses issued to the DPU RJ45 port are from the "network segments" (which is different than a DPU loopback) - the API in NICo is to create a Network Segment of type underlay on whatever the underlying network configuration is.  NICo issues two IPs to the RJ45 - (1) is the DPU OOB that's used to SSH to the ARM OS and NICo's management traffic, and (2) the DPU's BMC that is used for Redfish and DPU configuration.  There's also the host's BMC that needs to be also on a VLAN forwarding to the NICo DHCP relay.

**The host overlay interfaces addresses on top of vxlan and DPU is allocated via NICo through the control NIC on NICo, through overlay networking. So I assume no DHCP relay configuration needed on any switches. While is this overlay need to be manually configured on NICo control hosts' NIC?**

The DHCP relay is required only on the switches connected to the DPU OOBs/BMCs and Host BMCs.  The in-band ToRs just need to be configured for bgp unnumbered as "routed port".  The "overlay" networks that NICo will assign IPs from to the host are defined as "network segments" with the "overlay" type, then the overlay network is referenced when creating an instance.

**Do I need to separate the PXE of NICo like this as well to isolate the PXE installation process from site PXE server?**

There is a separate PXE server that NICo needs to serve its own images we ship as part of the software (i.e. DPU software, iPXE, etc). But if the DHCP is configured correctly and there's connectivity from the Host to the NICo PXE service, then it will be fine to live side-by-side.

**How does NICo select which bare metal to pick to satisfy the request for an instance? What selection criteria is supported?**

For the gRPC API, it doesn't, you pick the machine when calling "AllocateInstance" gRPC.  For the REST API, it has a concept of resource allocations, so a tenant would get an allocation of some number of a type of machine and then when creating an instance against that instance type it'd randomly pick one.  There's an API we're working on to do bulk allocations which will all get allocated on the same nvlink domain and another project to allocate by labels on the machine so you could choose machines in the same rack, etc.

**How is NICo made aware of power management endpoints (BMC IP and credentials) for bare metal?**

When you provision a NICo "site" you tell it which BMC subnets are provisioned on the network fabric, and then those subnets should be doing DHCP relaying to the NICo DHCP service.  When a BMC requests an IP, NICo allocates one and then looks up in an "expected machine" table for the initial username and password for that BMC (it looks it up by mac address, which NICo cross-references with the DHCP lease).  So you dont have to "pre-define" BMCs, but you do need to provide the initial mac address, username and password.

**Are there APIs to query and debug DPU state?**

DPUs will report health status (like if HBN is configured correctly, BGP peering, if the HBN container is running, that kind of thing) and heartbeat information, which version of the configuration has been applied; and also health checks for BMC-side health from the DPU's BMC for things like thermals and stuff. 

This information is also visible in the admin web UI. Furthermore, you can SSH to the DPU and poke around if the issue isn't obvious using these methods.
