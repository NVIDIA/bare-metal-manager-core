# Networking Requirements

This section outlines the networking requirements for NCX Infra Controller (NICo), including the necessary infrastructure, protocols, and performance standards.

Here is an overview of the requirements, which will be detailed in the following sections:

* **VNIs**: Datacenter-unique VNIs allocated based on the expected number of VPCs.
* **ASNs**: Globally-unique 32-bit ASNs allocated based on the expected number of DPUs.
* **IPv4 prefixes**: A single, globally-unique IPv4 prefix with a total IP allocation size based on the following formula: `(expected number of servers + the expected number of DPUs) * 2 + 2`
  * One or more additional, globally-unique IPv4 prefixes with a total IP allocation amount based on the following formula: `expected number of DPUs * 2`.  Minimum individual prefix size is /31.
* **Routing**: A mechanism for route-propagation and a default route for the tenant EVPN overlay network. Options for providing this include the following:
  * Allowing additional L2VPN-EVPN sessions with LEAF TORs and configuring the same sessions at each tier of the network (refer to simplified diagram below for reference).
  * Configuring a new set of devices to act as tenant gateways with an isolated tenant VRF, peering the new gateways with the core routers, and applying necessary route-leaking to inject a
    default route into the tenant VRF.

![Simplified diagram of the network topology](../static/ncp_overview.png)

## Underlay and BGP Configuration

* **Enable eBGP Unnumbered**: Configure on all leaf switches facing DPUs (RFC 5549).
* **Assign ASNs**: Allocate a pool of unique AS numbers based on the expected number of DPUs for the site.
* **Advertise Loopbacks**: Ensure DPUs advertise `/32` loopbacks for VxLAN tunnel endpoints.
* **VTEP to VTEP Connectivity**: Ensure DPUs receive either the `/32` advertised by all other DPUs, or an aggregate that contains them, or a default route at a minimum.
* **Route Filtering**:
  * Filter DPU announcements to only loopbacks.
  * Aggregate routes at the leaf/pod level where possible.
  * Set max-prefix limits on leaf switch ports facing DPUs.

## Overlay and EVPN Configuration

### Overlay Options

* **Option 1 - Dual-stacked IPv4/EVPN sessions with TOR**
  * Configure peering as follows:
    * TORs should be configured to accept EVPN sessions with the DPUs in addition to the existing IPv4 sessions.
    * At a minimum, spines should be configured for EVPN sessions with the TORs. Ideally, all tiers of the network should be configured with EVPN sessions.

* **Option 2 - Route-servers**
  * **Deploy Route Servers**: Set up at least two redundant BGP route servers (e.g. on-site controllers) for EVPN overlay peering.
  * **Configure Peering**: Establish multi-hop eBGP sessions (EVPN address family only) between DPUs and route servers.
  * **Disable IPv4 Unicast**: Ensure IPv4 unicast is disabled on overlay sessions.
 
 ### Providing a Default Route
 
Ensure that a default route is provided to the overlay. Options for providing this include the following:

* Allowing additional L2VPN-EVPN sessions with LEAF TORs and configuring the same sessions at each tier of your network.
* Configuring a new set of devices to act as tenant gateways with an isolated tenant VRF, peering the new gateways with your core routers, and applying the necessary route-leaking to inject a default route into the tenant VRF.


## Services and Integration

* **OOB DHCP Relay**: The OOB network should be configured with a DHCP relay to forward DHCP requests of BMCs to the Carbide DHCP service IP.

## Hardware/Physical

* **Cabling**: Connect DPUs to ToR/EoR switches (dual-homed recommended for redundancy).
* **Management Network**: Ensure separate out-of-band management connectivity for DPU BMCs.


## Autonomous System Number (ASN) Allocations

* **Unique ASN per DPU**: Every DPU will be assigned a unique ASN from a pool of ASNs given to Carbide. In multi-DPU hosts, each DPU will have its own unique ASN.
* **32-bit ASNs**: The use of 32-bit ASNs is required to ensure a sufficient number of unique numbers are available.
* **Architecture**: The [RFC 7938](https://datatracker.ietf.org/doc/html/rfc7938) guidelines should be followed for data center routing to prevent path hunting and loops.
* **Route-Servers (Optional)**: A specific ASN is needed for the BGP Route Servers (typically shared across the redundant route-server set).

## IP Allocations

* **L3VNI (Layer 3 VNI)**
  * **Tenant-Network**: One VNI for each expected VPC in a site. Each VPC requires a unique L3VNI that identifies their VRF.
* **L2VNI (Layer 2 VNI)**
  * **Admin Network**: A unique L2VNI is required for the admin network in a site.

## Route-Targets

The following are the standardized common route targets:

  * `:50100` **(Control-Plane/Service VIPs)**: Site Controller DPUs export service VIP routes with this tag.
  * `:50200` **(Internal Tenant Routes)**: Routes for VPCs designated as internal
  * `:50300` **(Maintenance)**: Routes for VPCs designated as used for maintenance
  * `:50400` **(Admin Network Routes)**: Routes belonging to the administrative network
  * `:50500` **(External Tenant Routes)**: Routes for VPCs designated as external

> [!NOTE]
> The route targets listed above are suggestions and can be changed, as long as all components agree. For example, if you choose an internal-common route target of 45001 instead of 50200, ensure both the config and the network are updated.

### Import/Export Policies

To ensure proper communication, the following mutual import/export relationships must be configured:

* **Tenant/Admin to Control Plane**: Networks exporting `:50200` through `:50500` must import `:50100`. This ensures tenant, admin, and maintenance networks can reach control-plane VIPs.
* **Control Plane to Tenant/Admin**: Site Controllers (or their routing equivalents) exporting `:50100` must import `:50200` through `:50500`. This ensures the control plane can reach all managed endpoints.

> [!NOTE]
> While many deployments align the route target number with the VNI for administrative simplicity, the routing policy is strictly governed by the route target import/export configuration, not the VNI itself.