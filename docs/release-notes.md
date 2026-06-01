# Release Notes

This document contains release notes for the NVIDIA Infra Controller (NICo) project.

## Infra Controller v0.8

### Highlights

- **Documentation refresh + unified REST API docs**: Updated the docs look and feel at [https://docs.nvidia.com/infra-controller/documentation/introduction](https://docs.nvidia.com/infra-controller/documentation/introduction), and consolidated REST API information into the same documentation set.
- **Simplified deployment**: Added NICo deployment [prerequisite tool](https://github.com/NVIDIA/ncx-infra-controller-core/tree/main/helm-prereqs) `helm-prereqs` to install required dependencies and enable easy NICo deployment.
- **Rack Level Administration (RLA)**: Significantly expanded rack/tray operations via REST APIs (validation, power, firmware, bring-up).

### Compatibility Matrix

The following components are supported for this release:

| Component            | Version |  
|----------------------|---------|
| NICo Core            | v0.8.0  |
| NICo REST API        | v1.4.2  |
| NICo REST Site Agent | v1.4.2  |

The following dependencies have been validated for this release:

| Component              | Version         |
|------------------------|-----------------|
| DPU NIC Firmware (BF3) | 32.47.2682      |
| HBN                    | 3.2.2-doca3.2.2 |

### Improvements

#### Deployment and Operations

- `helm-prereqs` deployment tool (Core):
  - Helm/Helmfile-driven installation of NICo prerequisites--including MetalLB, Zalando PostgreSQL Operator, cert-manager, HashiCorp Vault, and external-secrets--along with the main NICo components--NICo Core and NICo REST.
  - Includes orchestration and automation scripts such as `helmfile.yaml`, `setup.sh`, `preflight.sh`, and `clean.sh`.
  - This tool significantly reduces installation time compared to manual installation.
  - Location: [https://github.com/NVIDIA/ncx-infra-controller-core/tree/main/helm-prereqs](https://github.com/NVIDIA/ncx-infra-controller-core/tree/main/helm-prereqs)

#### Rack Level Administration (RLA)

- RLA REST API:
  - Rack endpoints (RLA-backed):
    - List racks / get rack by ID
    - Validate racks / validate rack by ID
    - Power control (single + batch)
    - Firmware update (single + batch)
    - Bring-up (single + batch)
- GB200 NVLink switches are now supported for lifecycle management.
- GB200 power shelves are now supported for lifecycle management.
- GB200 racks are now supported for lifecycle management:
  - At rack-level: rack bring up, power control, and firmware update
  - At tray-level: compute, NVSwitch, and powershelf tray operations

#### VPC and Routing

- BGP session password support has been added for peering sessions initiated by managed host DPUs.
- Instance creation/update now supports explicit IP selection within a VPC prefix.

#### BMC and Site Explorer

- The BMC now supports static IP address assignment.

#### Health and Observability

- Health alerts can now have a specified severity level, which is "Critical" by default. If the alert classification is greater than or equal to the severity level, it will appear as an alert. Otherwise, it will be ignored. Refer to the `crates/health/example/config.example.toml` file for more details.
- The REST API now supports NVUE health checks.
- NICo now supports NMX-T metric collection for switches.

#### Identity and Security

- Credentials APIs have been added—operators can manage BMC/UEFI credentials via API.
- The SuperNIC lockdown key management workflow has been implemented.
- Vault connections now enforce TLS verification.

#### Debug UI/CLI

- A new IPAM section has been added to the admin UI covering DHCP, DNS, and networks.
- An expected rack component details panel has been added to the admin UI.

#### Platform and Infrastructure

- `libredfish` has been updated from v0.39.2 to v0.43.10.
- The x86 QCOW imager has been updated to Ubuntu 24.04.

### Bug Fixes

#### VPC and Routing

- VPC peering VNI and prefix lists are now sorted deterministically in network config responses.

#### API Robustness and Validation

- Fixed Expected Machine OpenAPI issues around BMC default user fields.
- Standardized error handling and improved error attribution.
- Improved validation for RLA flows and addressed inventory/component-manager synchronization issues.
- Enhanced single and batch instance APIs for performance and clarity.
- Fixed typos/validation in `nvLinkLogicalPartitionId`.

#### Networking

- Strictly reject reserved IP addresses during interface update workflows.
- Made power status filterable for instance status queries.
- Reject unknown query parameters (400) to prevent typos from being silently ignored.

#### Security and Cleanup

- Required TLS certificates by default for IPAM and related services.
- Removed deprecated IPAM server code and cleaned up legacy DB relationships.

### Debug UI/CLI

- A hardcoded credential bug has been fixed in the debug UI.

## Infra Controller v0.2

This release of NICo is open-source software (OSS).

### Improvements

- The REST API now supports external identity providers (IdPs) for JWT authentication.
- The new `/nico/instance/batch` REST API endpoint allows for batch instance creation.
- Instances can now be rebooted by passing an `instance_id` argument, in addition to the existing `machine_id` argument.
- The State Controller is now split into two independent components: The `PeriodicEnqueuer`, which periodically enqueues state handling tasks using the `Enqueuer::enqueue_object` API for each resource/object managed by NICo, and the `StateProcessor`, which continuously de-queues the state handling tasks for each object type and executes the state handler on them.
- The state handler for objects is now scheduled again whenever the outcome of the state handler is `Transition`. This reduces the wait time for many state transitions by up to 30 seconds.
- The state handler is now re-scheduled for immediate execution if the DPU reports a different version from the previous check. This should reduce the time for wait states like `WaitingForNetworkConfig`.
- During the pre-ingestion phase, NICo will now set the time zone to UTC if it detects that time is out of sync. This allows the system to correctly interpret NTP timestamps from the time server.
- The Scout agent can now perform secure erase of NVMe devices asynchronously.
- NVLink interfaces are now marked as Pending when an update request is being sent.
- The update logic for NVLink Logical Partition inventory metadata has been improved.
- The `DpuExtensionService` now supports `name` as an argument for the `orderBy` parameter.
- NICo now supports bulk creation/update of `ExpectedMachine` objects.
- The Go version has been updated to v1.25.4.
- The `nv-redfish` package has been updated to v0.1.3.

### Bug Fixes

- The above `nv-redfish` package update fixes a critical bug with the BMC cache, which caused multiple cache miss errors, preventing the health monitor from re-discovery of monitored entities.

## Infra Controller EA

### What This Release Enables

- **Microservice**: Our goal is to make NICo deployable and independent of NGC dependencies, enabling a "Disconnected NICo" deployment model.
- **GB200 Support**: This release enables GB200 Node Ingestion and NVLink Partitioning, with the ability to provision both single and dual DPUs, ingest the GB200 compute trays, and validate the SKU. After ingestion, partners can create NVLink partitions, select instances, and configure the NVLink settings using the Admin CLI.
- **Deployment Flexibility**: The release includes both the source code and instructions to compile containers for NICo. Our goal is to make the NICo deployable and independent of NGC dependencies, enabling a "Disconnected NICo" deployment model.

### What You Can Test

The following key functionalities should be available for testing via the Admin CLI:

- **GB200 Node Ingestion**: Partners should be able to:
  - Install NICo.
  - Provision the DPUs (Dual DPUs are also supported).
  - Ingest the expected machines (GB200 compute trays).
  - Validate the SKU.
  - Assign instance types (Note that this currently requires encoding the rack location for GB200).
- **NVLink Partitioning**: Once the initial ingestion is complete, partners can do the following:
  - Create allocations and instances.
  - Create a partition.
  - Select an instance.
  - Set the NVLink configuration.
- **Disconnected NICo**: This release allows for operation without any dependency on NGC.

### Dependencies

| Category | Required Components | Description |
|----------|---------------------|-------------|
| Software | Vault, postgres, k8s cluster, Certificate Management, Temporal | Partners are required to bring in NICo dependencies |
| Hardware | Supported server and switch functionality(e.g. x86 nodes, specific NIC firmware, compatible BMCs, Switches that support BGP, EVPN, and RFC 5549 (unnumbered IPs)) | The code assumes predictable hardware attributes; unsupported SKUs may require custom configuration. |
| Network Topology | L2/L3 connectivity, DHCP/PXE servers, out-of-band management networks, specific switch side port configurations | All modules (e.g. discovery, provisioning) require pre-configured subnets and routing policies, as well as delegation of IP prefixes, ASN numbers, and EVPN VNI numbers. |
| External Systems | DNS resolvers/recursors, NTP, Authentication (Azure OIDC, Keycloak), Observability Stack | NICo provides clients with DNS resolver and NTP server information in the DHCP response. External authentication source that supports OIDC. NICo sends open-telemetry metrics and logs into an existing visualization/storage system |

**Supported Switches**:

- Optics Compatibility w/B3220 BF-3
- RFC5549 BGP Unnumbered routed ports
- IPv4/IPv6 Unicast BGP address family
- EVPN BGP address family
- LLDP
- BGP External AS
- DHCP Relay that supports Option 82
