# Release Notes

This document contains release notes for the Bare Metal Manager (BMM) project.

## Bare Metal Manager 0.2.0

This release of Bare Metal Manager is open source software.

### Improvements

- The REST API now supports external identity providers (IdPs) for JWT authentication.
- The new `/carbide/instance/batch` REST API endpoint allows for batch instances creation.
- Instances can now be rebooted by passing an `instance_id` argument, in addition to the existing `machine_id` argument.
- The State Controller is now split into two independent components: The `PeriodicEnqueuer`, which periodically enqueues state handling tasks using the `Enqueuer::enqueue_object` API for each resource/object managed by BMM, and the `StateProcessor`, which continuously de-queues the state handling tasks for each object type and executes the state handler on them.
- The state handler for objects is now scheduled again whenever the outcome of the state handler is `Transition`. This reduces the wait time for many state transitions by up to 30 seconds.
- The state handler is now re-scheduled for immediate execution if the DPU reports a different version from the previous check. This should reduce the time for wait states like `WaitingForNetworkConfig`.
- During the pre-ingestion phase, BMM will now set the time zone to UTC if it detects that time is out of sync. This allows the system to correctly interpret NTP timestamps from the time server.
- The Scout agent can now perform secure erase of NVMe devices asynchronously.
- NVLink interfaces are now marked as Pending when an update request is being sent.
- The update logic for NVLink Logical Partition inventory metadata has been improved.
- The `DpuExtensionService` now supports `name` as an argument for the `orderBy` parameter.
- BMM now supports bulk creation/update of `ExpectedMachine` objects.
- The Go version has been updated to v1.25.4.
- The `nv-redfish` package has been updated to v0.1.3.

### Bug Fixes

- The above `nv-redfish` package update fixes a critical bug with the BMC cache, which caused multiple cache miss errors, preventing the health monitor from re-discovery of monitored entities.

## Bare Metal Manager EA

### What This Release Enables

- **Microservice**: Our goal is to make BMM deployable and independent of NGC dependencies, enabling a "Disconnected BMM" deployment model.
- **GB200 Support**: This release enables GB200 Node Ingestion and NVLink Partitioning, with the ability to provision both single and dual DPUs, ingest the GB200 compute trays, and validate the SKU. After ingestion, partners can create NVLink partitions, select instances, and configure the NVLink settings using the Admin CLI.
- **Deployment Flexibility**: The release includes both the source code and instructions to compile containers for BMM. Our goal is to make the BMM deployable and independent of NGC dependencies, enabling a "Disconnected BMM" deployment model.

### What You Can Test

The following key functionalities should be available for testing via the Admin CLI:

- **GB200 Node Ingestion**: Partners should be able to:
  - Install BMM.
  - Provision the DPUs (Dual DPUs are also supported).
  - Ingest the expected machines (GB200 compute trays).
  - Validate the SKU.
  - Assign instance types (Note that this currently requires encoding the rack location for GB200).
- **NVLink Partitioning**: Once the initial ingestion is complete, partners can do the following:
  - Create allocations and instances.
  - Create a partition.
  - Select an instance.
  - Set the NVLink configuration.
- **Disconnected BMM**: This release allows for operation without any dependency on NGC.

### Dependencies

| Category | Required Components | Description |
|----------|---------------------|-------------|
| Software | Vault, postgres, k8s cluster, Certificate Management, Temporal | Partners are required to bring in BMM dependencies |
| Hardware | Supported server and switch functionality(e.g. x86 nodes, specific NIC firmware, compatible BMCs, Switches that support BGP, EVPN, and RFC 5549 (unnumbered IPs)) | The code assumes predictable hardware attributes; unsupported SKUs may require custom configuration. |
| Network Topology | L2/L3 connectivity, DHCP/PXE servers, out-of-band management networks, specific switch side port configurations | All modules (e.g. discovery, provisioning) require pre-configured subnets and routing policies, as well as delegation of IP prefixes, ASN numbers, and EVPN VNI numbers. |
| External Systems | DNS resolvers/recursers, NTP, Authentication (Azure OIDC, Keycloak), Observability Stack | BMM provides clients with DNS resolver and NTP server information in the DHCP response. External authentication source that supports OIDC. BMM sends open-telemetry metrics and logs into an existing visualization/storage system |

**Supported Switches**:

- Optics Compatibility w/B3220 BF-3
- RFC5549 BGP Unnumbered routed ports
- IPv4/IPv6 Unicast BGP address family
- EVPN BGP address family
- LLDP
- BGP External AS
- DHCP Relay that supports Option 82
