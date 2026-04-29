# DPU Configuration

NVIDIA Infra Controller (NICo) is a Bare-Metal-As-A-Service (BMaaS) solution. It manages the lifecycle of hosts, including user OS installation, host cleanup, validation tests, and automated software updates. It also provides host monitoring and virtualized private networking capabilities on ethernet and InfiniBand.

In order to enable virtual private networks (overlay networks), NICo utilizes DPUs as primary ethernet interfaces of hosts.

This document describes how NICo controls DPUs in order to achieve this behavior.

## Guiding Principles

The following guiding principles are for DPU configuration:

- Allow reconfiguration of DPU from any configuration into any other configuration with minimal complexity.
- Provide precise feedback on whether DPUs are configured as required, or whether stale configurations are present on the DPU.
- DPUs configurations can be reconstructed at any point in time (for example, if a firmware update and new operating system are installed on the DPU).

## Core Configuration Flow

DPUs are configured by the NICo site controller via a **declarative** and **stateless** mechanism:

- The agent running on DPUs (`dpu-agent`) requests the current desired configuration via the `GetManagedHostNetworkConfig` gRPC API call. Example data of the returned configuration is provided in the [Appendix](#dpu-configuration-example) below.
- Every configuration that is received from the site controller is converted into a [NVUE](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux/System-Configuration/NVIDIA-User-Experience-NVUE/) configuration file, which is then used to reconfigure HBN via the nvue CLI tool (`nv config apply`).
- The `dpu-agent` also reconfigures a DHCP server running on the DPU, which responds to DHCP requests from the attached host.
- After HBN and the DHCP server are reconfigured, `dpu-agent` implements health-checks that supervise whether the desired configurations are in-place and check whether the DPU is healthy (e.g. the agent continuously checks whether the DPU has established BGP peering with TORs and route servers according to the desired configuration).
- The `dpu-agent` uses the `RecordDpuNetworkStatus` gRPC API call to report back to the site control plane whether the desired configurations are applied, and whether all health checks are succeeding.
- For the first 30s after any configuration change, the DPU reports itself as unhealthy with a `PostConfigCheckWait` alert. This gives the DPU some time to monitor the stability and health of the new configuration before the site controller assumes that the new configuration is fully applied and operational.

```mermaid
sequenceDiagram
    box rgba(85, 102, 57, 0.2) Site Controller
        participant NICo as NICo API
    end

    box rgba(8, 143, 143, .2) DPU
        participant Agent as dpu-Agent
        participant Nvue as nvue
        participant Dhcp as DHCP Server
    end

    loop Every 30s
        Agent->>NICo: GetManagedHostNetworkConfig()<br>Returns desired configs and versions
        Agent->>Nvue: Apply requested configuration
        Agent->>Dhcp: Reconfigure DHCP Server
        Agent->>Agent: Health checks
        Agent->>NICo: RecordDpuNetworkStatus()<br>Report applied config versions<br>Report DPU health
    end
```

## Configuration Versioning

NICo uses versioned immutable configuration data in order to detect whether any intended changes have not yet been deployed:

- Every time a configuration for the DPU changes, an associated version number is increased.
- The version number is sent back from the DPU to the site controller as part of the `RecordDpuNetworkStatus` call.
- If the reported version number of the DPU does match the last desired version number and if the DPU reports itself as healthy/operational, the control plane knows that the configuration was deployed and can report that fact to tenants. If the version number does not match the desired version number, or if the DPU is not yet healthy, the instance will appear as `Provisioning`/`Configuring`/`Terminating` to the administrator.
- NICo will never show a configuration as applied without feedback from the DPU. Doing so would cause reliability issues (e.g. double-assignment of IPs), as well as raise security concerns.

The DPU configuration that is applied can be understood as coming from two different sources:

* **Tenant configurations**: While the host is under control of a tenant, the tenant can change the desired overlay network configuration. The tenant can e.g. control from which VPC prefix an IP address should be allocated for a given network interface. They can also decide how many Virtual Function interfaces (VFs) are utilized, and what their configuration is.
* **Site controller and host lifecycle**: During the lifecycle of a host, certain parts of the network configuration need to be updated. For example, when the host is provisioned for a tenant, the host networking gets reconfigured from using the admin overlay network towards the tenant overlay network. When the host is released by the tenant, it is moved back onto the admin network.

In order to separate these concerns, NICo internally uses two different configuration data structs and associated version numbers (`instance_network_config` versus `managedhost_network_config`). It can thereby distinguish whether a setting that is required by the tenant has not been applied, compared to whether a setting that is required by the control plane has not been applied.

Some example workflows that lead to updating configurations are shown in the following diagram:

```mermaid
sequenceDiagram
    actor User as NICo User

    box rgba(118, 185, 0, .2) Site Controller
        participant NICo as NICo API
    end

    box rgba(8, 143, 143, .2) DPU
        participant Agent as dpu-Agent
        participant Nvue as nvue
        participant Dhcp as DHCP Server
    end

    opt On Instance creation
        User ->> NICo: Create Instance
        NICo ->> NICo: Set Instance config and version<br>Update ManagedHost config (use_admin_network: false) and increment version
        Agent->>NICo: GetManagedHostNetworkConfig()<br>Returns desired configs and versions
        Agent->>Nvue: Apply requested configuration
        Agent->>Dhcp: Reconfigure DHCP Server
        Agent->>Agent: Health checks
        Agent->>NICo: RecordDpuNetworkStatus()<br>Report applied config versions<br>Report DPU health
        Note right of NICo: Transition Host between required states
        NICo ->> User: Report the Instance is Ready for usage
    end

    opt On Instance deletion
        NICo ->> NICo: Update ManagedHost config (use_admin_network: true)<br>and increment version
        Agent->>NICo: GetManagedHostNetworkConfig()<br>Returns desired configs and versions
        Agent->>Nvue: Apply requested configuration
        Agent->>Dhcp: Reconfigure DHCP Server
        Agent->>Agent: Health checks
        Agent->>NICo: RecordDpuNetworkStatus()<br>Report applied config versions<br>Report DPU health
        NICo->>NICo: Observe that expected ManagedHost network config is applied<br>Transition Host to cleanup states
        Note right of NICo: Additional Host cleanup
        NICo ->> User: Notify User that instance deletion succeeded
    end
```

## Host isolation

One important requirement for NICo is that Hosts/DPUs that are not confirmed to be part of the site are isolated from the remaining hosts on the site.

A DPU might get isolated from the cluster without the DPU software stack being erased (e.g. by site operators removing the knowledge of the DPU from the site database).

In order to satisfy the isolation requirements and to prevent unknown DPUs on the site from using resources (e.g. IPs on overlay networks), an additional mechanism is implemented: If the `GetManagedHostNetworkConfig` gRPC API call returns a `NotFound` error, the dpu-agent will configure the DPU/Host into an isolated mode.
The isolated configuration is only applied when the site controller is unaware of the DPU and its expected configuration. In case of any other errors (for example, intermittent communication issues), the DPU retains its last known configuration.

> **Note:** This is not the only mechanism that NICo utilizes to provide security on the networking layer. In addition to this, ACLs and routing table separation are used to implement secure virtual private networks (VPCs).

## Appendix

### DPU Configuration Example

```json
{
  "asn": 4294967000,
  "dhcp_servers": [
    "192.168.126.2"
  ],
  "vni_device": "vxlan48",
  "managed_host_config": {
    "loopback_ip": "192.168.96.36",
    "quarantine_state": null
  },
  "managed_host_config_version": "V3-T1733950583707475",
  "use_admin_network": false,
  "admin_interface": {
    "function_type": 0,
    "vlan_id": 14,
    "vni": 0,
    "gateway": "192.168.97.1/24",
    "ip": "192.168.97.49",
    "interface_prefix": "192.168.97.49/32",
    "virtual_function_id": null,
    "vpc_prefixes": [],
    "prefix": "192.168.97.0/24",
    "fqdn": "192.168-97-49.example.com",
    "booturl": null,
    "vpc_vni": 0,
    "svi_ip": null,
    "tenant_vrf_loopback_ip": null,
    "is_l2_segment": true,
    "vpc_peer_prefixes": [],
    "vpc_peer_vnis": [],
    "network_security_group": null
  },
  "tenant_interfaces": [
    {
      "function_type": 0,
      "vlan_id": 16,
      "vni": 1025032,
      "gateway": "192.168.98.1/26",
      "ip": "192.168.98.11",
      "interface_prefix": "192.168.98.11/32",
      "virtual_function_id": null,
      "vpc_prefixes": [
        "192.168.98.0/26"
      ],
      "prefix": "192.168.98.0/26",
      "fqdn": "192.168-98-11.unknowndomain",
      "booturl": null,
      "vpc_vni": 42,
      "svi_ip": null,
      "tenant_vrf_loopback_ip": null,
      "is_l2_segment": true,
      "vpc_peer_prefixes": [],
      "vpc_peer_vnis": [],
      "network_security_group": null
    }
  ],
  "instance_network_config_version": "V1-T1733950572461281",
  "instance_id": {
    "value": "b4c38910-9319-4bee-ac04-10cabb569a4c"
  },
  "network_virtualization_type": 2,
  "vpc_vni": 42,
  "route_servers": [
    "192.168.126.5",
    "192.168.126.11",
    "192.168.126.12"
  ],
  "remote_id": "c3046v74fnh6n4fs5kqvha0t76ub7ug7r9eh1dtilj0pe89eh99g",
  "deprecated_deny_prefixes": [
    "192.168.4.128/26",
    "192.168.98.0/24",
    "172.16.205.0/24"
  ],
  "dpu_network_pinger_type": "OobNetBind",
  "deny_prefixes": [],
  "site_fabric_prefixes": [
    "192.168.4.128/26",
    "192.168.98.0/24",
    "172.16.205.0/24"
  ],
  "vpc_isolation_behavior": 2,
  "stateful_acls_enabled": false,
  "enable_dhcp": true,
  "host_interface_id": "3912c59c-8fc0-400d-b05f-7bf62405018f",
  "min_dpu_functioning_links": null,
  "is_primary_dpu": true,
  "multidpu_enabled": false,
  "internet_l3_vni": null
}
```
