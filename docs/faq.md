# FAQs

This document contains frequently asked questions about Bare Metal Manager (BMM).

**Does BMM install Cumulus Linux onto ethernet switches?**

No, BMM does not install Cumulus Linux onto Ethernet switches.

**Does BMM install UFM?**

No, BMM does not install UFM, it is a dependency. BMM leverages existing UFM deployments for InfiniBand partition management via the UFM API using pkey. 

**Does BMM manage Infiniband switches in standalone mode (i.e. without UFM)?**

No, BMM does not manage Infiniband switches in standalone mode. It requires UFM for InfiniBand partitioning and fabric management. BMM calls UFM APIs to assign partition keys (P_Keys) for isolation.

**Does BMM maintain the database of the tenancy mappings of servers and ports?**

BMM knows if an instance is allocated or not, as well as its association to a VPC. BMM knows the switches that the DPU is plugged into via LLDP, so it can relay this information for the tenant on the machine to the network ports.

![BMM Tenancy Mapping](faq_tenency_mappings.png)

**Does BMM speak to NetQ to learn about the network?**

No, the BMM does not speak to NetQ.

**Does BMM install DPU OS?**

Yes, BMM installs the DPU OS, including all DPU firmware (BMC, NIC, UEFI). BMM also deploys HBN, a containerized service that packages the same core networking components (FRR, NVUE) that power Cumulus Linux.

**Does BMM bring up NVLink?**

No, BMM does not bring up NVLink. However, BMM manages NVLink partitions through NMX-M APIs. Plans to manage NVLink switches are being evaluated. 

**Does BMM support NVLink partitioning?**

Yes, BMM will support NVLink partitioning as part of a future release. 

**How does BMM maintain tenancy enforcement between Ethernet (N/S), Infiniband (E/W), NVLink (GPU-to-GPU) networks?**

* **Ethernet**: VXLAN with EVPN for VPC creation on DPU
* **E/W Ethernet (Spectrum-X)**: CX-based FW called DPA to do VXLan on CX (as part of future release)
* **Infiniband**: UFM-based partition key (P_Key) assignment
* **NVLInk**: NMX-M based partition management (as part of future release)

DPUs enforce Ethernet isolation in hardware, UFM enforces IB isolation, and NMX-M enforces NVLink isolation--all coordinated by BMM.

**When BMM is used to maintain tenancy enforcement for Ethernet (N/S), does it require access to make changes to SN switches running Cumulus or are all changes limited to HBN on the DPU?**

Ethernet tenancy enforcement is limited to HBN (Host-Based Networking) on the DPU and does not require BMM to make changes to Spectrum (SN) switches running Cumulus Linux.  BMM expects the switch configuration to provide BGP speakers on the Switches that speak IPv4 Unicast and L2/L3 EVPN address families, and “BGP Unnumbered” (RFC 5549)

**When BMM is used to maintain tenancy enforcement for Ethernet and hosts are presented to customers as bare metal, is OOB isolation of GPU/CPU host BMC managed as well or only the N/S overlay running on DPU?**

BMM configures the host BMC to disable connectivity from within the host to the BMC (e.g. Dell iDrac Lockdown, disabling KCS, etc), and also prevents access from the host (via network) to the BMC of the host. Effectively, the user cannot access the BMC of the bare metal hosts.  The BMC console (Serial console) is accessed by a user through a BMM service called SSH console that does Authentication and Authorization that the user accessing the console is the current owner of the machine.


**Can BMM be used to manage a portion of a cluster?**

BMM requires the N/S and OOB Ethernet DHCP relays pointed to the BMM DHCP service as well as access to UFM and NMX-M for E/W. Additionally, the EVPN topology must be visible to all nodes that are managed by the same cluster. If the DC operator wants to separate EVPN/DHCP into VLANs and VRFs, then you can arbitrarily assign nodes to BMM management or not. NMX-M and UFM are not multi–tenant aware, so there's a possibility of two things configuring NMX-M and UFM from interfering with each other.

**Can BMM be utilized for HGX platforms for host life cycle management?**

Yes, in addition to DGX as well as OEM/ODM CPU-only, Storage, etc nodes.

**Does BMM support installing an OS onto the servers? What OS’s are supported to install on BMM?**

Yes, BMM supports OS installation onto servers through PXE & Image-based. Any OS can be installed via iPXE (http://ipxe.org) that iPXE supports. OS management (patching, configuration, image generation) is the user’s responsibility. 

**What is the way to communicate with BMM? Does it expose an API? Does it have a shell interface?**

BMM exposes an API interface & authentication through JWT tokens or IdP integration (keycloak). There is also an admin-facing CLI & debugging/Engineering UI. 

**Where is BMM run? Is it a container/microservice? Is it a single container or a collection deployed via Helm?**

BMM runs on k8s cluster (3 or 5 control plane nodes recommended). It is a set of microservices for API, DNS, DHCP, Hardware Monitoring, BMC Console, Rack Management, etc.There is no helm chart for BMM today, it’s deployed with Kustomize Kubernetes manifests.

**Should I use BMM as my OS installation tool?**

BMM is more than an OS installation tool. It certainly helps with OS provisioning, but it's not the main use case for BMM. Automated Baremetal lifecycle management, network isolation & rack management are its key use cases.  This includes hardware burn-in testing, hardware completeness validation, Measured Boot for Firmware integrity and ongoing automated firmware updates, and out-of-band continuous hardware management.

**Do I need to change the OOB management TOR to configure a separate VLN for the BMM managed hosts and DPU (DPU OOB, Host OOB), with DHCP relay point to BMM DHCP?**

Yes, that's usually how it's done.  Each VLAN (sometimes the whole switch is a VLAN) - or SVI port - needs to have it's DHCP relay for the machines and DPUs you wish to manage with BMM pointing to BMM's DHCP server address you setup.

**Do I need to change existing infrastructure if separate VLANs are used?**

No, there is no need to change existing infrastructure if separate VLANs are used.

**With only one RJ45 on BF3, the DPU inband IP addresses allocation is part of DPU loopback allocated by BMM. Does it assume that the same management switch also supports DPU SSH access and that the DPU ssh IP is allocated by BMM and only accessible inside the data center?**

The IP addresses issued to the DPU RJ45 port are from the "network segments" (which is different than a DPU loopback) - the API in BMM is to create a Network Segment of type underlay on whatever the underlying network configuration is.  BMM issues two IPs to the RJ45 - (1) is the DPU OOB that's used to SSH to the ARM OS and BMM's management traffic, and (2) the DPU's BMC that is used for Redfish and DPU configuration.  There's also the host's BMC that needs to be also on a VLAN forwarding to the BMM DHCP relay.

**The host overlay interfaces addresses on top of vxlan and DPU is allocated via BMM through the control NIC on BMM, through overlay networking. So I assume no DHCP relay configuration needed on any switches. While is this overlay need to be manually configured on BMM control hosts' NIC?**

The DHCP relay is required only on the switches connected to the DPU OOBs/BMCs and Host BMCs.  The in-band ToRs just need to be configured for bgp unnumbered as "routed port".  The "overlay" networks that BMM will assign IPs from to the host are defined as "network segements" with the "overlay" type, then the overlay network is referenced when creating an instance.

**Do I need to seperate the PXE of BMM like this as well to isolate the PXE installation process from site PXE server?**

There is a separate PXE server that BMM needs to serve it's own images we ship as part of the software (i.e. DPU software, iPXE, etc). But if the DHCP is configured correctly and there's connectivity from the Host to the BMM PXE service, then it will be fine to live side-by-side.

**How does BMM select which bare metal to pick to satisfy the request for an instance? What selection criteria is supported?**

For the gRPC API, it doesn't, you pick the machine when calling "AllocateInstance" gRPC.  For the REST API, it has a concept of resource allocations, so a tenant would get an allocation of some number of a type of machine and then when creating an instance against that instance type it'd randomly pick one.  There's an API we're working on to do bulk allocations which will all get allocated on the same nvlink domain and another project to allocate by labels on the machine so you could choose machines in the same rack, etc.

**How is BMM made aware of power management endpoints (BMC IP and credentials) for bare metal?**

When you provision a BMM "site" you tell it which BMC subnets are provisioned on the network fabric, and then those subnets should be doing DHCP relaying to the BMM DHCP service.  When a BMC requests an IP, BMM allocates one and then looks up in an "expected machine" table for the initial username and password for that BMC (it looks it up by mac address, which BMM cross-references with the DHCP lease).  So you dont have to "pre-define" BMCs, but you do need to provide the initial mac address, username and password.

**Are there APIs to query and debug DPU state?**

DPUs will report health status (like if HBN is configured correctly, BGP peering, if the HBN container is running, that kind of thing) and heartbeat information, which version of the configuration has been applied; and also health checks for BMC-side health from the DPU's BMC for things like thermals and stuff.  You can always SSH to the DPU and poke around if the issue isn't obvious from the above. 
