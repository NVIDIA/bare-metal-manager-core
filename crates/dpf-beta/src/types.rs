/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! SDK types for the DPF SDK.

use crate::crds::dpus_generated::DpuStatusPhase;

/// Configuration for DPF initialization.
#[derive(Debug, Clone)]
pub struct DpfInitConfig {
    /// Namespace for DPF operator resources.
    pub namespace: String,
    /// URL for the BFB (BlueField Bundle) image (use public/upstream BFB).
    pub bfb_url: String,
    /// BMC password for DPU access.
    pub bmc_password: String,
    /// Name of the DPUDeployment CR (e.g. "carbide-deployment").
    pub deployment_name: String,
    /// Service templates and configs for M4 DPUDeployment.
    /// When empty, `default_services()` is used automatically.
    pub services: Vec<ServiceDefinition>,
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

/// Protocol for a config port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceConfigPortProtocol {
    Tcp,
    Udp,
}

/// Definition of a DPU service (DPUServiceTemplate + DPUServiceConfiguration).
#[derive(Debug, Clone, Default)]
pub struct ServiceDefinition {
    /// Service name (e.g. "dts", "carbide-services").
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

impl Default for DpfInitConfig {
    fn default() -> Self {
        Self {
            namespace: crate::NAMESPACE.to_string(),
            bfb_url: "http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb".to_string(),
            bmc_password: String::new(),
            deployment_name: "carbide-deployment".to_string(),
            services: Vec::new(),
        }
    }
}

/// Information about a DPU device (DPUDevice CR).
#[derive(Debug, Clone)]
pub struct DpuDeviceInfo {
    /// Name of the DPU device (DPUDevice CR name; matches operator label dpudevice-name).
    pub device_name: String,
    /// BMC IP address for the DPU.
    pub dpu_bmc_ip: String,
    /// BMC IP address for the host.
    pub host_bmc_ip: String,
    /// Serial number of the DPU.
    pub serial_number: String,
}

/// Information about a DPU node (host with DPUs).
#[derive(Debug, Clone)]
pub struct DpuNodeInfo {
    /// Stable identifier for the node (e.g. host machine ID).
    pub node_id: String,
    /// BMC IP of the host.
    pub host_bmc_ip: String,
    /// Names of the DPU devices (DPUDevice CR names) attached to this node.
    pub dpu_device_names: Vec<String>,
}

/// Phase of DPU lifecycle.
///
/// This is a simplified view - the DPF operator has many more internal phases,
/// but Carbide only cares about these actionable states.
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
