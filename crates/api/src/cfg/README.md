# Carbide API Configuration Reference

This document describes every section and field in the `nico-api-config.toml`
configuration file, which is deserialized into `CarbideConfig` (defined in
`file.rs`). Fields are listed in declaration order. Defaults are noted where
applicable.

---

## `CarbideConfig` (top-level)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | `SocketAddr` | `[::]:1079` | Socket address for the gRPC API server. |
| `listen_only` | `bool` | `false` | Run passively (no background services, RPC/web only). Used in dev mode. |
| `metrics_endpoint` | `Option<SocketAddr>` | — | Socket address for the Prometheus `/metrics` HTTP server. |
| `alt_metric_prefix` | `Option<String>` | — | Alternative metric prefix emitted alongside `carbide_` for dashboard migration. |
| `database_url` | `String` | **required** | Postgres connection string for all persistent state. |
| `max_database_connections` | `u32` | `1000` | Maximum database connection pool size. |
| `ib_config` | `Option<IBFabricConfig>` | — | InfiniBand fabric configuration (see [IBFabricConfig](#ibfabricconfig)). |
| `asn` | `u32` | **required** | Autonomous System Number, fixed per environment. Used by nico-dpu-agent for `frr.conf` BGP routing. |
| `dhcp_servers` | `Vec<String>` | `[]` | DHCP server addresses announced to DPUs during network provisioning. |
| `route_servers` | `Vec<String>` | `[]` | Route server IPs for L2VPN Ethernet Virtual network support. |
| `enable_route_servers` | `bool` | `false` | Enables route server injection into DPU FRR configs for L2VPN. |
| `deny_prefixes` | `Vec<Ipv4Network>` | `[]` | IPv4 CIDR prefixes that tenant instances are blocked from reaching. Generates iptables DROP rules and nvue ACL policies. |
| `site_fabric_prefixes` | `Vec<IpNetwork>` | `[]` | IP prefixes (v4/v6) assigned for tenant use within this site. |
| `anycast_site_prefixes` | `Vec<Ipv4Network>` | `[]` | Aggregate IPv4 prefixes containing tenant-announced prefixes (e.g., BYOIP). |
| `common_tenant_host_asn` | `Option<u32>` | — | ASN that tenants use to peer with the DPU. If unset, any ASN is accepted. |
| `vpc_isolation_behavior` | `VpcIsolationBehaviorType` | `MutualIsolation` | VPC isolation policy: `mutual_isolation` or `open`. |
| `dpu_network_monitor_pinger_type` | `Option<String>` | — | Pinger implementation type (e.g., `"OobNetBind"`) for DPU link health checks. |
| `tls` | `Option<TlsConfig>` | — | TLS certificate/key paths (see [TlsConfig](#tlsconfig)). |
| `listen_mode` | `ListenMode` | `Tls` | Transport mode: `plaintext_http1`, `plaintext_http2`, or `tls`. |
| `auth` | `Option<AuthConfig>` | — | Authentication/authorization settings (see [AuthConfig](#authconfig)). |
| `pools` | `Option<HashMap<String, ResourcePoolDef>>` | — | Resource pools that allocate IPs, VNIs, etc. Required but `Option` for partial-config merging. |
| `networks` | `Option<HashMap<String, NetworkDefinition>>` | — | Networks created at startup. Alternative: `CreateNetworkSegment` gRPC. |
| `dpu_ipmi_tool_impl` | `Option<String>` | — | IPMI tool implementation for DPU power control (`"prod"` or `"fake"`). |
| `dpu_ipmi_reboot_attempts` | `Option<u32>` | — | Retry count when IPMI errors during DPU reboot. |
| `ib_fabrics` | `HashMap<String, IbFabricDefinition>` | `{}` | InfiniBand fabrics managed by the site. Currently only one fabric is supported. |
| `initial_domain_name` | `Option<String>` | — | Domain to create if none exist. Most sites use a single domain. |
| `initial_dpu_agent_upgrade_policy` | `Option<AgentUpgradePolicyChoice>` | — | Policy for nico-dpu-agent upgrades. Also settable via `nico-admin-cli`. |
| `max_concurrent_machine_updates` | `Option<i32>` | — | **Deprecated.** Use `machine_updater` instead. |
| `machine_update_run_interval` | `Option<u64>` | — | Interval (seconds) at which the machine update manager checks for updates. |
| `site_explorer` | `SiteExplorerConfig` | *(see below)* | SiteExplorer hardware discovery settings (see [SiteExplorerConfig](#siteexplorerconfig)). |
| `nvue_enabled` | `bool` | `true` | DPU agent uses NVUE for config instead of writing files directly. |
| `vpc_peering_policy` | `Option<VpcPeeringPolicy>` | — | Policy for VPC peering based on network virtualization type at creation time. |
| `vpc_peering_policy_on_existing` | `Option<VpcPeeringPolicy>` | — | Policy for whether existing VPC peerings should be active. |
| `attestation_enabled` | `bool` | `false` | Enables TPM-based machine attestation (adds `Measuring` state before `Ready`). |
| `tpm_required` | `bool` | `true` | Require TPM module for machine registration. **Testing only** when `false`. |
| `machine_state_controller` | `MachineStateControllerConfig` | *(see below)* | Machine state controller timing (see [MachineStateControllerConfig](#machinestatecontrollerconfig)). |
| `network_segment_state_controller` | `NetworkSegmentStateControllerConfig` | *(see below)* | Network segment state controller timing. |
| `ib_partition_state_controller` | `IbPartitionStateControllerConfig` | *(see below)* | IB partition state controller timing. |
| `dpa_interface_state_controller` | `DpaInterfaceStateControllerConfig` | *(see below)* | DPA interface state controller timing. |
| `rack_state_controller` | `RackStateControllerConfig` | *(see below)* | Rack state controller timing. |
| `power_shelf_state_controller` | `PowerShelfStateControllerConfig` | *(see below)* | Power shelf state controller timing. |
| `switch_state_controller` | `SwitchStateControllerConfig` | *(see below)* | Switch state controller timing. |
| `spdm_state_controller` | `SpdmStateControllerConfig` | *(see below)* | SPDM state controller timing. |
| `host_models` | `HashMap<String, Firmware>` | `{}` | Maps host model identifiers to firmware definitions for BMC/UEFI/NIC upgrades. |
| `firmware_global` | `FirmwareGlobal` | *(see below)* | Global firmware update settings (see [FirmwareGlobal](#firmwareglobal)). |
| `machine_updater` | `MachineUpdater` | *(see below)* | Machine update policies (see [MachineUpdater](#machineupdater)). |
| `max_find_by_ids` | `u32` | `100` | Max IDs accepted by `find_*_by_ids` APIs. |
| `network_security_group` | `NetworkSecurityGroupConfig` | *(see below)* | NSG settings (see [NetworkSecurityGroupConfig](#networksecuritygroupconfig)). |
| `min_dpu_functioning_links` | `Option<u32>` | — | Minimum functioning DPU links for healthy status. If unset, all must work. |
| `host_health` | `HostHealthConfig` | *(default)* | Host health monitoring thresholds for hardware health and DPU agent compliance. |
| `internet_l3_vni` | `u32` | `100001` | Network infrastructure-provided L3 VNI for FNN VPC Internet connectivity. Combined with `datacenter_asn` for route-target. |
| `measured_boot_collector` | `MeasuredBootMetricsCollectorConfig` | *(see below)* | Measured boot metrics exporter (see [MeasuredBootMetricsCollectorConfig](#measuredbootmetricscollectorconfig)). |
| `machine_validation_config` | `MachineValidationConfig` | *(see below)* | Machine validation tests (see [MachineValidationConfig](#machinevalidationconfig)). |
| `machine_identity` | `MachineIdentityConfig` | *(see below)* | SPIFFE JWT-SVID machine identity (see [MachineIdentityConfig](#machineidentityconfig)). |
| `bypass_rbac` | `bool` | `false` | Disables RBAC enforcement. **Testing/dev only.** |
| `dpu_config` | `DpuConfig` | *(see below)* | DPU firmware and provisioning (see [DpuConfig](#dpuconfig)). |
| `fnn` | `Option<FnnConfig>` | — | FNN L3 VNI overlay networking (see [FnnConfig](#fnnconfig)). |
| `bom_validation` | `BomValidationConfig` | *(see below)* | BOM/SKU validation (see [BomValidationConfig](#bomvalidationconfig)). |
| `bios_profiles` | `BiosProfileVendor` | *(default)* | BIOS profiles by vendor/model for Redfish BIOS management. |
| `selected_profile` | `BiosProfileType` | *(default)* | Default BIOS profile type applied to machines. |
| `dpa_config` | `Option<DpaConfig>` | — | Cluster Interconnect (east-west Ethernet) config (see [DpaConfig](#dpaconfig)). |
| `dsx_exchange_event_bus` | `Option<DsxExchangeEventBusConfig>` | — | MQTT event bus for publishing state transitions (see [DsxExchangeEventBusConfig](#dsxexchangeeventbusconfig)). |
| `datacenter_asn` | `u32` | `11414` | Datacenter ASN used by FNN for DC-specific route targets. |
| `nvlink_config` | `Option<NvLinkConfig>` | — | NvLink partitioning via NMX-M (see [NvLinkConfig](#nvlinkconfig)). |
| `power_manager_options` | `PowerManagerOptions` | *(see below)* | Power management timing (see [PowerManagerOptions](#powermanageroptions)). |
| `sitename` | `Option<String>` | — | Human-readable site name exposed to tenants via FMDS. |
| `auto_machine_repair_plugin` | `AutoMachineRepairPluginConfig` | *(default)* | Auto-repair configuration for failed machines. |
| `vmaas_config` | `Option<VmaasConfig>` | — | VMaaS configuration for VM system integration. |
| `mlxconfig_profiles` | `Option<HashMap<String, MlxConfigProfile>>` | — | Named Mellanox NIC register configuration profiles for superNIC firmware flashing. TOML key: `mlx-config-profiles`. |
| `rack_management_enabled` | `bool` | `false` | Standalone infrastructure manager mode for GB200/GB300/VR144. See doc comment for full behavioral changes. |
| `force_dpu_nic_mode` | `bool` | `false` | Treat DPUs as regular NICs (skip managed DPU config). For dev labs with BF DPUs. |
| `rms_api_url` | `Option<String>` | — | Rack Manager Service API URL for rack-level firmware and power operations. |
| `rack_types` | `RackTypeConfig` | *(default)* | Rack type definitions referenced by expected racks. |
| `spdm` | `SpdmConfig` | *(see below)* | SPDM hardware attestation (see [SpdmConfig](#spdmconfig)). |
| `bgp_leaf_session_password` | `Option<BgpLeafSessionPassword>` | — | Selects the credential source for leaf-facing BGP session passwords returned to agents in managed host network config. Supported value: `site_wide`. |
| `site_global_vpc_vni` | `Option<u32>` | — | Forces all VRFs to share a single VNI (Cumulus Linux route-leaking workaround). Limits DPU to one VRF. |
| `dpf` | `DpfConfig` | *(see below)* | DPF (DPU Platform Framework) Kubernetes deployment (see [DpfConfig](#dpfconfig)). |
| `x86_pxe_boot_url_override` | `Option<String>` | — | Override PXE boot URL for x86 machines. |
| `arm_pxe_boot_url_override` | `Option<String>` | — | Override PXE boot URL for ARM machines. |
| `compute_allocation_enforcement` | `ComputeAllocationEnforcement` | `WarnOnly` | Controls enforcement of compute allocations on new instance requests. |
| `supernic_firmware_profiles` | nested `HashMap` | `{}` | SuperNIC firmware profiles keyed by `part_number` then `PSID`. |
| `component_manager` | `Option<ComponentManagerConfig>` | — | Component manager for NvLink switches and power shelves. |

---

## Sub-Structs

### `TlsConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `root_cafile_path` | `String` | `""` | Root CA certificate for client validation. |
| `identity_pemfile_path` | `String` | `""` | Server identity certificate PEM. |
| `identity_keyfile_path` | `String` | `""` | Server identity private key. |
| `admin_root_cafile_path` | `String` | `""` | Admin root CA for admin client validation. |

### `AuthConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `permissive_mode` | `bool` | — | Enable permissive authorization (dev mode). |
| `casbin_policy_file` | `Option<PathBuf>` | — | Path to Casbin CSV policy file. |
| `cli_certs` | `Option<AllowedCertCriteria>` | — | Additional allowed cert criteria for nico-admin-cli. |
| `trust` | `Option<TrustConfig>` | — | SPIFFE trust domain and allowed paths for client certs. |

### `IBFabricConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enables InfiniBand fabric management. |
| `max_partition_per_tenant` | `i32` | `31` | Maximum IB partitions per tenant (1-31). |
| `allow_insecure` | `bool` | `false` | Allow insecure fabric configs that skip tenant isolation. |
| `mtu` | `IBMtu` | *(default)* | MTU for IB fabric traffic. |
| `rate_limit` | `IBRateLimit` | *(default)* | Rate limit for IB traffic. |
| `service_level` | `IBServiceLevel` | *(default)* | QoS service level for IB packets. |
| `fabric_monitor_run_interval` | `Duration` | `60s` | Interval for the IB fabric monitor. |

### `NvLinkConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enables NvLink partitioning. |
| `monitor_run_interval` | `Duration` | `60s` | NvLink monitor polling interval. |
| `nmx_m_operation_timeout` | `Duration` | `10s` | Timeout for pending NMX-M operations. |
| `nmx_m_endpoint` | `String` | `"localhost"` | NMX-M endpoint (host:port). |
| `allow_insecure` | `bool` | `false` | Skip TLS verification for NMX-M. |

### `SiteExplorerConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enables hardware discovery. |
| `run_interval` | `Duration` | `120s` | Interval between exploration runs. |
| `concurrent_explorations` | `u64` | `30` | Max nodes explored in parallel. |
| `explorations_per_run` | `u64` | `90` | Max nodes explored per run. |
| `create_machines` | `bool` | `true` | Auto-create ManagedHost state machines. Dynamically toggleable. |
| `machines_created_per_run` | `u64` | `4` | Max ManagedHosts created per run. |
| `rotate_switch_nvos_credentials` | `bool` | `false` | Auto-rotate switch NVOS admin credentials. |
| `override_target_ip` | `Option<String>` | — | **Deprecated.** Use `bmc_proxy`. Debug BMC IP override. |
| `override_target_port` | `Option<u16>` | — | **Deprecated.** Use `bmc_proxy`. Debug BMC port override. |
| `allow_zero_dpu_hosts` | `bool` | `false` | Allow hosts with zero DPUs (set `false` in prod). |
| `bmc_proxy` | `HostPortPair` | — | BMC proxy host:port for integration testing/dev. |
| `allow_changing_bmc_proxy` | `Option<bool>` | *(auto)* | Allow runtime changes to `bmc_proxy`. Auto-detected from initial config. |
| `reset_rate_limit` | `Duration` | `1h` | Minimum time between SiteExplorer-initiated BMC resets. |
| `admin_segment_type_non_dpu` | `bool` | `false` | Non-DPU hosts use `HostInband` admin segment type. |
| `allocate_secondary_vtep_ip` | `bool` | `false` | Allocate secondary VTEP IP for GENEVE traffic intercept. |
| `create_power_shelves` | `bool` | `false` | Auto-create Power Shelf state machines. |
| `explore_power_shelves_from_static_ip` | `bool` | `false` | Discover power shelves via static IP. |
| `power_shelves_created_per_run` | `u64` | `1` | Max power shelves created per run. |
| `create_switches` | `bool` | `false` | Auto-create Switch state machines. |
| `switches_created_per_run` | `u64` | `9` | Max switches created per run. |
| `use_onboard_nic` | `bool` | `false` | Use onboard NIC instead of DPU NICs. |
| `explore_mode` | `SiteExplorerExploreMode` | `LibRedfish` | Redfish backend: `libredfish`, `nv-redfish`, or `compare-result`. |

### `StateControllerConfig`

Shared by all `*StateControllerConfig` structs (machine, network segment, IB
partition, DPA interface, rack, power shelf, switch, SPDM).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `iteration_time` | `Duration` | `30s` | Target duration for one state controller iteration. |
| `max_object_handling_time` | `Duration` | `3m` | Timeout for evaluating/advancing a single object's state. |
| `max_concurrency` | `usize` | `10` | Max objects advanced in parallel. |
| `processor_dispatch_interval` | `Duration` | `2s` | Max wait time when checking for and dispatching new tasks. |
| `processor_log_interval` | `Duration` | `60s` | How often the processor emits log messages. |
| `metric_emission_interval` | `Duration` | `60s` | How often aggregate metrics are recalculated. |
| `metric_hold_time` | `Duration` | `5m` | How long per-object metrics are held before eviction. |

### `MachineStateControllerConfig`

Extends `StateControllerConfig` with:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dpu_wait_time` | `Duration` | `5m` | Time before a DPU is considered definitively down. |
| `power_down_wait` | `Duration` | `2m` | Wait after power-down before powering on. |
| `failure_retry_time` | `Duration` | `30m` | Time before re-triggering reboot if machine hasn't called back. |
| `dpu_up_threshold` | `Duration` | `5m` | Max time without DPU health report before assuming it's down. |
| `scout_reporting_timeout` | `Duration` | `5m` | Duration without scout report before host is unhealthy. |
| `uefi_boot_wait` | `Duration` | `5m` | Wait time for UEFI boot completion after host reboot. |

### `NetworkSegmentStateControllerConfig`

Extends `StateControllerConfig` with:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network_segment_drain_time` | `Duration` | `5m` | Time a network segment must have 0 allocated IPs before release. |

### `FirmwareGlobal`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `autoupdate` | `bool` | `false` | Enable automatic host firmware updates. |
| `host_enable_autoupdate` | `Vec<String>` | `[]` | Host models to force-enable autoupdate. |
| `host_disable_autoupdate` | `Vec<String>` | `[]` | Host models to force-disable autoupdate. |
| `run_interval` | `Duration` | `30s` | Firmware manager polling interval. |
| `max_uploads` | `usize` | `4` | Max concurrent firmware uploads. |
| `concurrency_limit` | `usize` | `16` | Max concurrent firmware flashing operations. |
| `firmware_directory` | `PathBuf` | `/opt/carbide/firmware` | Firmware binary storage directory. |
| `host_firmware_upgrade_retry_interval` | `Duration` | `60m` | Retry delay for failed host firmware upgrades. |
| `instance_updates_manual_tagging` | `bool` | `true` | Require manual tagging before firmware updates. |
| `no_reset_retries` | `bool` | `false` | Disable retry logic after BMC resets. |
| `hgx_bmc_gpu_reboot_delay` | `Duration` | `30s` | Delay after GPU reboot before HGX BMC access. |
| `requires_manual_upgrade` | `bool` | `false` | Force all firmware upgrades to require admin approval. |

### `MachineUpdater`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `instance_autoreboot_period` | `Option<TimePeriod>` | — | UTC time window for automatic machine reboots. |
| `max_concurrent_machine_updates_absolute` | `Option<i32>` | — | Hard cap on concurrent machine updates. |
| `max_concurrent_machine_updates_percent` | `Option<i32>` | — | Percentage cap on concurrent updates (lesser of absolute/percent is used). |

### `PowerManagerOptions`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable power management. |
| `next_try_duration_on_success` | `Duration` | `5m` | Retry interval after successful power operation. |
| `next_try_duration_on_failure` | `Duration` | `2m` | Retry interval after failed power operation. |
| `wait_duration_until_host_reboot` | `Duration` | `15m` | Wait after power-down before powering on host. |

### `DpuConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dpu_nic_firmware_initial_update_enabled` | `bool` | `false` | Enable DPU NIC firmware updates on initial discovery. |
| `dpu_nic_firmware_reprovision_update_enabled` | `bool` | `true` | Enable DPU NIC firmware updates on reprovisioning. |
| `dpu_models` | `HashMap<String, Firmware>` | *(BF2+BF3 defaults)* | DPU model firmware definitions. |
| `dpu_nic_firmware_update_versions` | `Vec<String>` | *(BF2+BF3 NIC versions)* | DPU NIC firmware version strings. |
| `dpu_enable_secure_boot` | `bool` | `false` | Enable secure boot flow for DPU provisioning via Redfish. |

### `NetworkSecurityGroupConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_network_security_group_size` | `u32` | `200` | Max expanded rules per NSG. |
| `stateful_acls_enabled` | `bool` | `true` | Enable stateful ACLs (toggled on DPU via nvue). |
| `policy_overrides` | `Vec<NetworkSecurityGroupRule>` | `[]` | NSG rules injected before user-defined rules. |

### `FnnConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `admin_vpc` | `Option<AdminFnnConfig>` | — | FNN configuration for the admin network VPC. |
| `common_internal_route_target` | `Option<RouteTargetConfig>` | — | Double-tag for internal tenant routes (consumed by the network infrastructure). |
| `additional_route_target_imports` | `Vec<RouteTargetConfig>` | `[]` | Extra route targets imported on DPU VRFs. |
| `routing_profiles` | `HashMap<String, FnnRoutingProfileConfig>` | `{}` | Named per-VPC routing profiles. |

### `DpaConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable Cluster Interconnect Network. |
| `mqtt_endpoint` | `String` | `"mqtt.nico"` | MQTT broker host for DPA. |
| `mqtt_broker_port` | `u16` | `1884` | MQTT broker port. |
| `subnet_ip` | `Ipv4Addr` | `0.0.0.0` | Base IPv4 address of the DPA subnet. |
| `subnet_mask` | `i32` | `0` | CIDR prefix length for the DPA subnet. |
| `hb_interval` | `Duration` | `2m` | Heartbeat interval for DPA health checks. |
| `auth` | `MqttAuthConfig` | *(none)* | MQTT authentication settings. |

### `DsxExchangeEventBusConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the DSX Exchange Event Bus. |
| `mqtt_endpoint` | `String` | `"mqtt.nico"` | MQTT broker host. |
| `mqtt_broker_port` | `u16` | `1884` | MQTT broker port. |
| `publish_timeout` | `Duration` | `1s` | Timeout for MQTT publish operations. |
| `queue_capacity` | `usize` | `1024` | Event buffer size (events dropped when full). |
| `auth` | `MqttAuthConfig` | *(none)* | MQTT authentication settings. |

### `DpfConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable DPF Kubernetes deployment. |
| `bfb_url` | `String` | `""` | BlueField firmware bundle URL. |
| `deployment_name` | `Option<String>` | — | Kubernetes deployment name. |
| `services` | `Option<Vec<DpfServiceConfig>>` | — | Additional Helm services. |

### `SpdmConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable SPDM hardware attestation. |
| `nras_config` | `Option<nras::Config>` | — | NRAS configuration for secure boot verification. |

### `MachineIdentityConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Master switch for machine identity APIs (opt-in; set `true` with `current_encryption_key_id` and credentials). |
| `algorithm` | `String` | `"ES256"` | Signing algorithm for per-org keys. |
| `token_ttl_min_sec` | `u32` | `60` | Minimum token TTL in seconds. |
| `token_ttl_max_sec` | `u32` | `86400` | Maximum token TTL in seconds. |
| `token_endpoint_http_proxy` | `Option<String>` | — | HTTP proxy for token endpoint calls (SSRF mitigation). |

### `MeasuredBootMetricsCollectorConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable measured boot metrics export. |
| `run_interval` | `Duration` | `60s` | Polling interval for boot measurement data. |

### `MachineValidationConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable machine validation tests. |
| `test_selection_mode` | `MachineValidationTestSelectionMode` | `Default` | `Default`, `EnableAll`, or `DisableAll`. |
| `run_interval` | `Duration` | `60s` | Validation check interval. |
| `tests` | `Vec<MachineValidationTestConfig>` | `[]` | Per-test enable/disable overrides. |

### `BomValidationConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable BOM/SKU validation. |
| `ignore_unassigned_machines` | `bool` | `false` | Let machines without a SKU bypass validation. |
| `allow_allocation_on_validation_failure` | `bool` | `false` | Keep machines allocatable even when validation fails. |
| `find_match_interval` | `Duration` | `5m` | Interval between SKU match attempts. |
| `auto_generate_missing_sku` | `bool` | `false` | Auto-create missing SKUs from expected machines. |
| `auto_generate_missing_sku_interval` | `Duration` | `5m` | Interval between auto-generate attempts. |

### `MqttAuthConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `auth_mode` | `MqttAuthMode` | `None` | `none`, `basic_auth`, or `oauth2`. |
| `oauth2` | `Option<MqttOAuth2Config>` | — | OAuth2 settings (required when `auth_mode` is `oauth2`). |

### `MqttOAuth2Config`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `token_url` | `String` | **required** | OAuth2 token endpoint URL. |
| `scopes` | `Vec<String>` | `[]` | OAuth2 scopes to request. |
| `http_timeout` | `Duration` | `30s` | Token endpoint HTTP timeout. |
| `username` | `String` | `"oauth2token"` | Username in MQTT CONNECT packet. |
