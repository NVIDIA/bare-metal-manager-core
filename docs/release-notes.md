# Release Notes

## Carbide EA

### What This Release Enables

- **Microservice**: Our goal is to make Carbide deployable and independent of NGC dependencies, enabling a "Disconnected Carbide" deployment model.
- **GB200 Support**: This release enables GB200 Node Ingestion and NVLink Partitioning, with the ability to provision both single and dual DPUs, ingest the GB200 compute trays, and validate the SKU. After ingestion, partners can create NVLink partitions, select instances, and configure the NVLink settings using the Admin CLI.
- **Deployment Flexibility**: The release includes both the source code and instructions to compile containers for Carbide. Our goal is to make the Carbide deployable and independent of NGC dependencies, enabling a "Disconnected Carbide" deployment model.

### What You Can Test

The following key functionalities should be available for testing via the Admin CLI:

- **GB200 Node Ingestion**: Partners should be able to:
  - Install Carbide.
  - Provision the DPUs (Dual DPUs are also supported).
  - Ingest the expected machines (GB200 compute trays).
  - Validate the SKU.
  - Assign instance types (Note that this currently requires encoding the rack location for GB200).
- **NVLink Partitioning**: Once the initial ingestion is complete, partners can do the following:
  - Create allocations and instances.
  - Create a partition.
  - Select an instance.
  - Set the NVLink configuration.
- **Disconnected Carbide**: This release allows for operation without any dependency on NGC.

### Dependencies

| Category | Required Components | Description |
|----------|---------------------|-------------|
| Software | Vault, postgres, k8s cluster, Certificate Management, Temporal | Partners are required to bring in Carbide dependencies |
| Hardware | Supported server and switch functionality(e.g. x86 nodes, specific NIC firmware, compatible BMCs, Switches that support BGP, EVPN, and RFC 5549 (unnumbered IPs)) | The code assumes predictable hardware attributes; unsupported SKUs may require custom configuration. |
| Network Topology | L2/L3 connectivity, DHCP/PXE servers, out-of-band management networks, specific switch side port configurations | All modules (e.g. discovery, provisioning) require pre-configured subnets and routing policies, as well as delegation of IP prefixes, ASN numbers, and EVPN VNI numbers. |
| External Systems | DNS resolvers/recursers, NTP, Authentication (Azure OIDC, Keycloak), Observability Stack | Carbide provides clients with DNS resolver and NTP server information in the DHCP response. External authentication source that supports OIDC. Carbide sends open-telemetry metrics and logs into an existing visualization/storage system |

**Supported Switches**:

- Optics Compatibility w/B3220 BF-3
- RFC5549 BGP Unnumbered routed ports
- IPv4/IPv6 Unicast BGP address family
- EVPN BGP address family
- LLDP
- BGP External AS
- DHCP Relay that supports Option 82
