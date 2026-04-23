/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! SDK types for the DPF SDK.

use crate::crds::dpus_generated::DpuStatusPhase;

/// Async provider for BMC passwords used to create and refresh the K8s BMC
/// secret. Implement this trait to supply credentials dynamically (e.g. from
/// a vault or credential manager).
#[async_trait::async_trait]
pub trait BmcPasswordProvider: Send + Sync {
    async fn get_bmc_password(&self) -> Result<String, crate::DpfError>;
}

#[async_trait::async_trait]
impl BmcPasswordProvider for String {
    async fn get_bmc_password(&self) -> Result<String, crate::DpfError> {
        Ok(self.clone())
    }
}

/// Service name constants for use across crates
pub const DOCA_HBN_SERVICE_NAME: &str = "doca-hbn";
pub const DHCP_SERVER_SERVICE_NAME: &str = "carbide-dhcp-server";
pub const FMDS_SERVICE_NAME: &str = "carbide-fmds";

/// Configuration for creating DPF operator resources (BFB, DPUFlavor,
/// DPUDeployment, service templates, etc.) during initialization.
#[derive(Debug, Clone)]
pub struct InitDpfResourcesConfig {
    /// URL for the BFB (BlueField Bundle) image.
    pub bfb_url: String,
    /// Name of the DPUDeployment CR.
    pub deployment_name: String,
    /// Name of the DPUFlavor CR.
    pub flavor_name: String,
    /// Service templates and configs for M4 DPUDeployment.
    /// When empty, `default_services()` is used automatically.
    pub services: Vec<ServiceDefinition>,
    /// Rendered bf.cfg template content for the DPU configuration ConfigMap.
    /// When set, a ConfigMap is created during initialization.
    pub bfcfg_template: Option<String>,
}

impl Default for InitDpfResourcesConfig {
    fn default() -> Self {
        Self {
            bfb_url: String::new(),
            deployment_name: "dpu-deployment".to_string(),
            flavor_name: crate::flavor::DEFAULT_FLAVOR_NAME.to_string(),
            services: Vec::new(),
            bfcfg_template: None,
        }
    }
}

/// Service type for configPorts (DPUServiceConfiguration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPortsServiceType {
    NodePort,
    ClusterIp,
    None,
}

/// Single port entry for DPUServiceConfiguration.serviceConfiguration.configPorts.
#[derive(Debug, Clone)]
pub struct ServiceConfigPort {
    pub name: String,
    pub port: i64,
    pub protocol: ServiceConfigPortProtocol,
    pub node_port: Option<i64>,
}

/// Service Network Attachment Definition (NAD)
#[derive(Debug, Clone)]
pub enum ServiceNADResourceType {
    Vf,
    Sf,
    Veth,
}

#[derive(Debug, Clone)]
pub struct ServiceNAD {
    pub name: String,
    pub bridge: Option<String>,
    pub ipam: Option<bool>,
    pub resource_type: ServiceNADResourceType,
    pub mtu: Option<i64>,
}

/// Protocol for a config port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceConfigPortProtocol {
    Tcp,
    Udp,
}

/// Definition of a DPU service (DPUServiceTemplate + DPUServiceConfiguration).
#[derive(Debug, Clone, Default)]
pub struct ServiceDefinition {
    /// Service name (e.g. "dts").
    pub name: String,
    /// Helm chart repository URL.
    pub helm_repo_url: String,
    /// Helm chart name.
    pub helm_chart: String,
    /// Helm chart version.
    pub helm_version: String,
    /// Optional helm values for the template (merged into chart).
    pub helm_values: Option<serde_json::Value>,
    /// Network interfaces for the service.
    pub interfaces: Vec<ServiceInterface>,
    /// Optional service configuration (helm values for DPUServiceConfiguration).
    pub config_values: Option<serde_json::Value>,
    /// Config ports for DPUServiceConfiguration (e.g. DTS httpserverport 9100).
    pub config_ports: Option<Vec<ServiceConfigPort>>,
    /// Service type for config_ports (e.g. None for DTS).
    pub config_ports_service_type: Option<ConfigPortsServiceType>,
    /// Service chain switches connecting physical interfaces to this service's interfaces.
    pub service_chain_switches: Vec<ServiceChainSwitch>,
    /// Optional annotations for the service DaemonSet (e.g. Multus CNI networks).
    pub service_daemon_set_annotations: Option<std::collections::BTreeMap<String, String>>,
    /// Optional service Network Attachment Definition specification
    pub service_nad: Option<ServiceNAD>,
}

/// Service Network Attachment Definition (NAD)
#[derive(Debug, Clone)]
pub enum DpuServiceInterfaceTemplateType {
    Vlan,
    Physical,
    Pf,
    Vf,
    Ovn,
    Service,
}

/// Network interface for a DPU service.
#[derive(Debug, Clone)]
pub struct DpuServiceInterfaceTemplateDefinition {
    /// Interface name.
    pub name: String,
    /// Interface Type
    pub iface_type: DpuServiceInterfaceTemplateType,
    /// PF Interface ID
    pub pf_id: i64,
    /// VF Interface ID
    pub vf_id: i64,
    /// Chained service interfaces vector
    pub chained_svc_if: Option<Vec<(String, String)>>,
}

/// Network interface for a DPU service.
#[derive(Debug, Clone)]
pub struct ServiceInterface {
    /// Interface name.
    pub name: String,
    /// Network name.
    pub network: String,
}

/// Service chain switch connecting a physical interface to a service interface.
#[derive(Debug, Clone)]
pub struct ServiceChainSwitch {
    /// Physical interface label (e.g. "p0", "p1", "pf0hpf").
    pub physical_interface: String,
    /// Service name (e.g. "doca-hbn").
    pub service_name: String,
    /// Interface name on the service (e.g. "p0_if").
    pub service_interface: String,
}

impl ServiceDefinition {
    /// Create a service definition with the required helm chart fields.
    pub fn new(
        name: impl Into<String>,
        helm_repo_url: impl Into<String>,
        helm_chart: impl Into<String>,
        helm_version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            helm_repo_url: helm_repo_url.into(),
            helm_chart: helm_chart.into(),
            helm_version: helm_version.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DpuFlavorBridgeDefinition {
    pub vf_intercept_bridge_name: String,
    pub vf_intercept_bridge_port: String,
    pub host_intercept_bridge_name: String,
    pub host_intercept_bridge_port: String,
    pub vf_intercept_bridge_sf: String,
}

/// Information about a DPU device (DPUDevice CR).
#[derive(Debug, Clone)]
pub struct DpuDeviceInfo {
    /// Identifier for this device (e.g. `01-02-03-04-05-06`).
    /// Used as the DPUDevice CR name.
    pub device_id: String,
    /// BMC IP address for the DPU.
    pub dpu_bmc_ip: String,
    /// BMC IP address for the host.
    pub host_bmc_ip: String,
    /// Serial number of the DPU.
    pub serial_number: String,
    /// Caller-defined identifier for the host machine.
    /// Passed through to the labeler for resource labels.
    pub host_machine_id: String,
    /// Caller-defined identifier for the DPU machine.
    /// Passed through to the labeler for resource labels.
    pub dpu_machine_id: String,
}

/// Information about a DPU node (host with DPUs).
#[derive(Debug, Clone)]
pub struct DpuNodeInfo {
    /// Identifier for this node (e.g. `01-02-03-04-05-06`).
    /// Used to build the DPUNode CR name via `dpu_node_cr_name()`.
    pub node_id: String,
    /// BMC IP of the host.
    pub host_bmc_ip: String,
    /// Identifiers of each device attached to this node.
    pub device_ids: Vec<String>,
    /// Caller-defined identifier for the host machine.
    /// Passed through to the labeler for contextual node labels.
    pub host_machine_id: String,
}

/// Phase of DPU lifecycle.
///
/// This is a simplified view - the DPF operator has many more internal phases,
/// but callers typically only care about these actionable states.
/// Provisioning sub-phases are represented as Provisioning(detail) so the
/// detailed phase is still visible for debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpuPhase {
    /// DPU is being provisioned by the operator.
    Provisioning(String),
    /// DPU is waiting on node effect (maintenance hold).
    NodeEffect,
    /// Host reboot required before DPU can progress.
    Rebooting,
    /// DPU is ready and operational.
    Ready,
    /// DPU is in an error state.
    Error,
    /// DPU is being deleted.
    Deleting,
}

impl AsRef<str> for DpuPhase {
    fn as_ref(&self) -> &str {
        match self {
            DpuPhase::Provisioning(detail) => detail.as_str(),
            DpuPhase::NodeEffect => "NodeEffect",
            DpuPhase::Rebooting => "Rebooting",
            DpuPhase::Ready => "Ready",
            DpuPhase::Error => "Error",
            DpuPhase::Deleting => "Deleting",
        }
    }
}

impl std::fmt::Display for DpuPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl From<DpuStatusPhase> for DpuPhase {
    fn from(phase: DpuStatusPhase) -> Self {
        match phase {
            DpuStatusPhase::Initializing => Self::Provisioning("Initializing".into()),
            DpuStatusPhase::NodeEffect => Self::NodeEffect,
            DpuStatusPhase::Pending => Self::Provisioning("Pending".into()),
            DpuStatusPhase::ConfigFwParameters => Self::Provisioning("ConfigFwParameters".into()),
            DpuStatusPhase::PrepareBfb => Self::Provisioning("PrepareBfb".into()),
            DpuStatusPhase::OsInstalling => Self::Provisioning("OsInstalling".into()),
            DpuStatusPhase::DpuClusterConfig => Self::Provisioning("DpuClusterConfig".into()),
            DpuStatusPhase::HostNetworkConfiguration => {
                Self::Provisioning("HostNetworkConfiguration".into())
            }
            DpuStatusPhase::Ready => Self::Ready,
            DpuStatusPhase::Error => Self::Error,
            DpuStatusPhase::Deleting => Self::Deleting,
            DpuStatusPhase::Rebooting => Self::Rebooting,
            DpuStatusPhase::InitializeInterface => Self::Provisioning("InitializeInterface".into()),
            DpuStatusPhase::CheckingHostRebootRequired => Self::Rebooting,
            DpuStatusPhase::NodeEffectRemoval => Self::NodeEffect,
        }
    }
}

/// Event emitted on any DPU resource change.
///
/// This event fires for every observed update to a DPU, not only when the
/// phase transitions. Handlers must be idempotent and tolerate receiving
/// the same phase multiple times.
#[derive(Debug, Clone)]
pub struct DpuEvent {
    /// Name of the DPU resource.
    pub dpu_name: String,
    /// DPU device name (DPUDevice CR name; matches operator label dpudevice-name).
    pub device_name: String,
    /// Name of the DPUNode containing this DPU.
    pub node_name: String,
    /// Observed phase.
    pub phase: DpuPhase,
}

/// Event emitted when a DPU is in the Rebooting phase.
#[derive(Debug, Clone)]
pub struct RebootRequiredEvent {
    /// Name of the DPU resource.
    pub dpu_name: String,
    /// Name of the DPUNode resource.
    pub node_name: String,
    /// Host BMC IP.
    pub host_bmc_ip: String,
}

/// Event emitted when a DPU is in the NodeEffect phase.
#[derive(Debug, Clone)]
pub struct MaintenanceEvent {
    /// Name of the DPU resource.
    pub dpu_name: String,
    /// Name of the DPUNode resource.
    pub node_name: String,
}

/// Event emitted when a DPU is in the Ready phase.
#[derive(Debug, Clone)]
pub struct DpuReadyEvent {
    /// Name of the DPU resource.
    pub dpu_name: String,
    /// DPU device name (DPUDevice CR name).
    pub device_name: String,
    /// Name of the DPUNode containing this DPU.
    pub node_name: String,
}

/// Event emitted when a DPU is in the Error phase.
#[derive(Debug, Clone)]
pub struct DpuErrorEvent {
    /// Name of the DPU resource.
    pub dpu_name: String,
    /// DPU device name (DPUDevice CR name).
    pub device_name: String,
    /// Name of the DPUNode containing this DPU.
    pub node_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpu_phase_from_status() {
        assert_eq!(DpuPhase::from(DpuStatusPhase::Ready), DpuPhase::Ready);
        assert_eq!(DpuPhase::from(DpuStatusPhase::Error), DpuPhase::Error);
        assert_eq!(DpuPhase::from(DpuStatusPhase::Deleting), DpuPhase::Deleting);
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::Rebooting),
            DpuPhase::Rebooting
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::Initializing),
            DpuPhase::Provisioning("Initializing".into())
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::Pending),
            DpuPhase::Provisioning("Pending".into())
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::OsInstalling),
            DpuPhase::Provisioning("OsInstalling".into())
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::NodeEffect),
            DpuPhase::NodeEffect
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::CheckingHostRebootRequired),
            DpuPhase::Rebooting
        );
        assert_eq!(
            DpuPhase::from(DpuStatusPhase::NodeEffectRemoval),
            DpuPhase::NodeEffect
        );
    }

    #[test]
    fn test_dpu_phase_equality() {
        assert_eq!(DpuPhase::Ready, DpuPhase::Ready);
        assert_ne!(
            DpuPhase::Ready,
            DpuPhase::Provisioning("Initializing".into())
        );
        assert_eq!(DpuPhase::Rebooting, DpuPhase::Rebooting);
    }
}
