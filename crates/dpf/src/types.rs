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

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

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

pub const DPU_AGENT_SERVICE_NAME: &str = "carbide-dpu-agent";
pub const OTEL_COLLECTOR_SERVICE_NAME: &str = "carbide-otelcol";
pub const DTS_SERVICE_NAME: &str = "dts";

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

    pub proxy: Option<DpfProxyDetails>,
}

impl Default for InitDpfResourcesConfig {
    fn default() -> Self {
        Self {
            bfb_url: String::new(),
            deployment_name: "dpu-deployment".to_string(),
            flavor_name: crate::flavor::DEFAULT_FLAVOR_NAME.to_string(),
            services: Vec::new(),
            proxy: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpfProxyDetails {
    pub https_proxy: String,
    #[serde(default)]
    pub no_proxy: Vec<String>,
}

/// A DPU CR whose installed BFB or `spec.dpuFlavor` does not match the
/// expected one. Returned by [`crate::DpfSdk::find_outdated_dpus_dpf`]; the
/// labels map is the DPU CR's `metadata.labels` so callers can map back to
/// their own identifiers.
#[derive(Debug, Clone)]
pub struct DpuMismatch {
    pub dpu_cr_name: String,
    pub dpu_labels: std::collections::BTreeMap<String, String>,
    /// Expected BFB filename (e.g. `<namespace>-bf-bundle-<sha256>.bfb`).
    pub target_bfb: String,
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
    /// Config ports for DPUServiceConfiguration (e.g. DTS httpserverport 9189).
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
    pub dpu_bmc_ip: IpAddr,
    /// BMC IP address for the host.
    pub host_bmc_ip: IpAddr,
    /// Serial number of the DPU.
    pub serial_number: String,
    /// Caller-defined identifier for the DPU machine.
    /// Passed through to the labeler for resource labels.
    pub dpu_machine_id: String,
    /// is _primary dpu?
    pub is_primary: bool,
}

/// Information about a DPU node (host with DPUs).
#[derive(Debug, Clone)]
pub struct DpuNodeInfo {
    /// Identifier for this node (e.g. `01-02-03-04-05-06`).
    /// Used to build the DPUNode CR name via `dpu_node_cr_name()`.
    pub node_id: String,
    /// BMC IP of the host.
    pub host_bmc_ip: IpAddr,
    /// Identifiers of each device attached to this node.
    pub device_ids: Vec<String>,
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
            DpuStatusPhase::DpuConfig => Self::Provisioning("DpuConfig".into()),
            DpuStatusPhase::PerformArmForceRestart => {
                Self::Provisioning("PerformArmForceRestart".into())
            }
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
    pub host_bmc_ip: IpAddr,
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

/// Curated snapshot of the DPF CRs related to a single host. Produced by
/// [`crate::DpfSdk::snapshot_host`]. Designed for ad-hoc inspection (e.g.
/// printing as JSON from an admin CLI), not as a stable wire format.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostDpfSnapshot {
    pub dpu_node: Option<DpuNodeSummary>,
    pub dpu_devices: Vec<DpuDeviceSummary>,
    pub dpus: Vec<DpuSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DpuNodeSummary {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub dpu_device_refs: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DpuDeviceSummary {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub bmc_ip: Option<String>,
    pub bmc_port: Option<i32>,
    pub serial_number: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DpuSummary {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub spec_bfb: String,
    pub spec_dpu_flavor: Option<String>,
    pub spec_dpu_device_name: String,
    pub spec_dpu_node_name: String,
    pub status_phase: Option<String>,
    pub status_bfb_file: Option<String>,
}

/// Helm-chart version observed on a live `DPUServiceTemplate` CR. Used by
/// [`crate::DpfSdk::list_service_template_versions`] so callers (e.g. the
/// admin CLI) can compare configured vs deployed versions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceTemplateVersion {
    pub cr_name: String,
    pub deployment_service_name: String,
    pub helm_repo_url: String,
    pub helm_chart: Option<String>,
    pub helm_version: String,
    /// Docker image tag extracted from `helm_chart.values.image.tag`, if
    /// present. Empty when the template doesn't pin an image (e.g. dts
    /// relies on the chart default).
    pub docker_image_tag: String,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    /// `DpuPhase::from(DpuStatusPhase)` is a total conversion; every operator
    /// status phase maps to exactly one simplified `DpuPhase`. This folds the
    /// old `test_dpu_phase_from_status` and enumerates all 17 source variants,
    /// including each provisioning sub-phase that collapses into
    /// `Provisioning(detail)`.
    #[test]
    fn dpu_phase_from_status_maps_every_variant() {
        check_values(
            [
                Check {
                    scenario: "Initializing -> Provisioning",
                    input: DpuStatusPhase::Initializing,
                    expect: DpuPhase::Provisioning("Initializing".into()),
                },
                Check {
                    scenario: "Pending -> Provisioning",
                    input: DpuStatusPhase::Pending,
                    expect: DpuPhase::Provisioning("Pending".into()),
                },
                Check {
                    scenario: "ConfigFwParameters -> Provisioning",
                    input: DpuStatusPhase::ConfigFwParameters,
                    expect: DpuPhase::Provisioning("ConfigFwParameters".into()),
                },
                Check {
                    scenario: "PrepareBfb -> Provisioning",
                    input: DpuStatusPhase::PrepareBfb,
                    expect: DpuPhase::Provisioning("PrepareBfb".into()),
                },
                Check {
                    scenario: "OsInstalling -> Provisioning",
                    input: DpuStatusPhase::OsInstalling,
                    expect: DpuPhase::Provisioning("OsInstalling".into()),
                },
                Check {
                    scenario: "DpuClusterConfig -> Provisioning",
                    input: DpuStatusPhase::DpuClusterConfig,
                    expect: DpuPhase::Provisioning("DpuClusterConfig".into()),
                },
                Check {
                    scenario: "HostNetworkConfiguration -> Provisioning",
                    input: DpuStatusPhase::HostNetworkConfiguration,
                    expect: DpuPhase::Provisioning("HostNetworkConfiguration".into()),
                },
                Check {
                    scenario: "InitializeInterface -> Provisioning",
                    input: DpuStatusPhase::InitializeInterface,
                    expect: DpuPhase::Provisioning("InitializeInterface".into()),
                },
                Check {
                    scenario: "DpuConfig -> Provisioning",
                    input: DpuStatusPhase::DpuConfig,
                    expect: DpuPhase::Provisioning("DpuConfig".into()),
                },
                Check {
                    scenario: "PerformArmForceRestart -> Provisioning",
                    input: DpuStatusPhase::PerformArmForceRestart,
                    expect: DpuPhase::Provisioning("PerformArmForceRestart".into()),
                },
                Check {
                    scenario: "NodeEffect -> NodeEffect",
                    input: DpuStatusPhase::NodeEffect,
                    expect: DpuPhase::NodeEffect,
                },
                Check {
                    scenario: "NodeEffectRemoval -> NodeEffect",
                    input: DpuStatusPhase::NodeEffectRemoval,
                    expect: DpuPhase::NodeEffect,
                },
                Check {
                    scenario: "Rebooting -> Rebooting",
                    input: DpuStatusPhase::Rebooting,
                    expect: DpuPhase::Rebooting,
                },
                Check {
                    scenario: "CheckingHostRebootRequired -> Rebooting",
                    input: DpuStatusPhase::CheckingHostRebootRequired,
                    expect: DpuPhase::Rebooting,
                },
                Check {
                    scenario: "Ready -> Ready",
                    input: DpuStatusPhase::Ready,
                    expect: DpuPhase::Ready,
                },
                Check {
                    scenario: "Error -> Error",
                    input: DpuStatusPhase::Error,
                    expect: DpuPhase::Error,
                },
                Check {
                    scenario: "Deleting -> Deleting",
                    input: DpuStatusPhase::Deleting,
                    expect: DpuPhase::Deleting,
                },
            ],
            DpuPhase::from,
        );
    }

    /// `AsRef<str>` for `DpuPhase` renders each variant to its canonical name;
    /// a provisioning phase renders its detail string verbatim. Covers all six
    /// `DpuPhase` variants, including an empty-detail provisioning phase.
    #[test]
    fn dpu_phase_as_ref_renders_each_variant() {
        check_values(
            [
                Check {
                    scenario: "provisioning renders its detail",
                    input: DpuPhase::Provisioning("OsInstalling".into()),
                    expect: "OsInstalling".to_string(),
                },
                Check {
                    scenario: "provisioning with empty detail renders empty",
                    input: DpuPhase::Provisioning(String::new()),
                    expect: String::new(),
                },
                Check {
                    scenario: "node effect",
                    input: DpuPhase::NodeEffect,
                    expect: "NodeEffect".to_string(),
                },
                Check {
                    scenario: "rebooting",
                    input: DpuPhase::Rebooting,
                    expect: "Rebooting".to_string(),
                },
                Check {
                    scenario: "ready",
                    input: DpuPhase::Ready,
                    expect: "Ready".to_string(),
                },
                Check {
                    scenario: "error",
                    input: DpuPhase::Error,
                    expect: "Error".to_string(),
                },
                Check {
                    scenario: "deleting",
                    input: DpuPhase::Deleting,
                    expect: "Deleting".to_string(),
                },
            ],
            |phase| phase.as_ref().to_string(),
        );
    }

    /// `Display` for `DpuPhase` delegates to `AsRef<str>`, so `to_string()`
    /// yields the same canonical name for every variant.
    #[test]
    fn dpu_phase_display_matches_as_ref() {
        check_values(
            [
                Check {
                    scenario: "provisioning renders its detail",
                    input: DpuPhase::Provisioning("Pending".into()),
                    expect: "Pending".to_string(),
                },
                Check {
                    scenario: "node effect",
                    input: DpuPhase::NodeEffect,
                    expect: "NodeEffect".to_string(),
                },
                Check {
                    scenario: "rebooting",
                    input: DpuPhase::Rebooting,
                    expect: "Rebooting".to_string(),
                },
                Check {
                    scenario: "ready",
                    input: DpuPhase::Ready,
                    expect: "Ready".to_string(),
                },
                Check {
                    scenario: "error",
                    input: DpuPhase::Error,
                    expect: "Error".to_string(),
                },
                Check {
                    scenario: "deleting",
                    input: DpuPhase::Deleting,
                    expect: "Deleting".to_string(),
                },
            ],
            |phase| phase.to_string(),
        );
    }

    /// `PartialEq` for `DpuPhase`: same variant compares equal, different
    /// variants differ, and `Provisioning` discriminates on its detail string.
    /// Folds the old `test_dpu_phase_equality`.
    #[test]
    fn dpu_phase_equality_distinguishes_variants() {
        check_values(
            [
                Check {
                    scenario: "ready equals ready",
                    input: (DpuPhase::Ready, DpuPhase::Ready),
                    expect: true,
                },
                Check {
                    scenario: "rebooting equals rebooting",
                    input: (DpuPhase::Rebooting, DpuPhase::Rebooting),
                    expect: true,
                },
                Check {
                    scenario: "error equals error",
                    input: (DpuPhase::Error, DpuPhase::Error),
                    expect: true,
                },
                Check {
                    scenario: "deleting equals deleting",
                    input: (DpuPhase::Deleting, DpuPhase::Deleting),
                    expect: true,
                },
                Check {
                    scenario: "node effect equals node effect",
                    input: (DpuPhase::NodeEffect, DpuPhase::NodeEffect),
                    expect: true,
                },
                Check {
                    scenario: "provisioning equals same-detail provisioning",
                    input: (
                        DpuPhase::Provisioning("Pending".into()),
                        DpuPhase::Provisioning("Pending".into()),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "ready differs from provisioning",
                    input: (
                        DpuPhase::Ready,
                        DpuPhase::Provisioning("Initializing".into()),
                    ),
                    expect: false,
                },
                Check {
                    scenario: "ready differs from error",
                    input: (DpuPhase::Ready, DpuPhase::Error),
                    expect: false,
                },
                Check {
                    scenario: "rebooting differs from node effect",
                    input: (DpuPhase::Rebooting, DpuPhase::NodeEffect),
                    expect: false,
                },
                Check {
                    scenario: "provisioning differs by detail",
                    input: (
                        DpuPhase::Provisioning("Pending".into()),
                        DpuPhase::Provisioning("OsInstalling".into()),
                    ),
                    expect: false,
                },
            ],
            |(a, b)| a == b,
        );
    }

    /// `ConfigPortsServiceType` derives `PartialEq`; each variant equals itself
    /// and differs from the others.
    #[test]
    fn config_ports_service_type_equality() {
        check_values(
            [
                Check {
                    scenario: "node port equals node port",
                    input: (
                        ConfigPortsServiceType::NodePort,
                        ConfigPortsServiceType::NodePort,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "cluster ip equals cluster ip",
                    input: (
                        ConfigPortsServiceType::ClusterIp,
                        ConfigPortsServiceType::ClusterIp,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "none equals none",
                    input: (ConfigPortsServiceType::None, ConfigPortsServiceType::None),
                    expect: true,
                },
                Check {
                    scenario: "node port differs from cluster ip",
                    input: (
                        ConfigPortsServiceType::NodePort,
                        ConfigPortsServiceType::ClusterIp,
                    ),
                    expect: false,
                },
                Check {
                    scenario: "cluster ip differs from none",
                    input: (
                        ConfigPortsServiceType::ClusterIp,
                        ConfigPortsServiceType::None,
                    ),
                    expect: false,
                },
            ],
            |(a, b)| a == b,
        );
    }

    /// `ServiceConfigPortProtocol` derives `PartialEq`; Tcp and Udp are
    /// distinct and each equals itself.
    #[test]
    fn service_config_port_protocol_equality() {
        check_values(
            [
                Check {
                    scenario: "tcp equals tcp",
                    input: (
                        ServiceConfigPortProtocol::Tcp,
                        ServiceConfigPortProtocol::Tcp,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "udp equals udp",
                    input: (
                        ServiceConfigPortProtocol::Udp,
                        ServiceConfigPortProtocol::Udp,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "tcp differs from udp",
                    input: (
                        ServiceConfigPortProtocol::Tcp,
                        ServiceConfigPortProtocol::Udp,
                    ),
                    expect: false,
                },
            ],
            |(a, b)| a == b,
        );
    }

    /// `InitDpfResourcesConfig::default()` seeds the documented defaults: an
    /// empty BFB URL and services list, the `dpu-deployment` name, the crate
    /// default flavor, and no proxy. Probe each field independently.
    #[test]
    fn init_dpf_resources_config_default_fields() {
        check_values(
            [Check {
                scenario: "bfb url is empty",
                input: (),
                expect: true,
            }],
            |()| InitDpfResourcesConfig::default().bfb_url.is_empty(),
        );
        check_values(
            [Check {
                scenario: "deployment name",
                input: (),
                expect: "dpu-deployment".to_string(),
            }],
            |()| InitDpfResourcesConfig::default().deployment_name,
        );
        check_values(
            [Check {
                scenario: "flavor name uses crate default",
                input: (),
                expect: crate::flavor::DEFAULT_FLAVOR_NAME.to_string(),
            }],
            |()| InitDpfResourcesConfig::default().flavor_name,
        );
        check_values(
            [Check {
                scenario: "services is empty",
                input: (),
                expect: 0usize,
            }],
            |()| InitDpfResourcesConfig::default().services.len(),
        );
        check_values(
            [Check {
                scenario: "proxy is none",
                input: (),
                expect: true,
            }],
            |()| InitDpfResourcesConfig::default().proxy.is_none(),
        );
    }

    /// `ServiceDefinition::new` records the four required helm fields and
    /// leaves every optional field at its `Default`. Each row reads one field
    /// off the freshly constructed value.
    #[test]
    fn service_definition_new_records_required_fields() {
        let build = || ServiceDefinition::new("dts", "https://repo.example", "dts-chart", "1.2.3");

        check_values(
            [Check {
                scenario: "name",
                input: (),
                expect: "dts".to_string(),
            }],
            |()| build().name,
        );
        check_values(
            [Check {
                scenario: "helm repo url",
                input: (),
                expect: "https://repo.example".to_string(),
            }],
            |()| build().helm_repo_url,
        );
        check_values(
            [Check {
                scenario: "helm chart",
                input: (),
                expect: "dts-chart".to_string(),
            }],
            |()| build().helm_chart,
        );
        check_values(
            [Check {
                scenario: "helm version",
                input: (),
                expect: "1.2.3".to_string(),
            }],
            |()| build().helm_version,
        );
        // Each row reads one optional field off the freshly built definition
        // and asserts it sits at its `Default` (None / empty).
        enum OptionalField {
            HelmValuesIsNone,
            ConfigValuesIsNone,
            ConfigPortsIsNone,
            ConfigPortsServiceTypeIsNone,
            ServiceNadIsNone,
            ServiceDaemonSetAnnotationsIsNone,
            InterfacesEmpty,
            ServiceChainSwitchesEmpty,
        }
        check_values(
            [
                Check {
                    scenario: "helm values default to none",
                    input: OptionalField::HelmValuesIsNone,
                    expect: true,
                },
                Check {
                    scenario: "config values default to none",
                    input: OptionalField::ConfigValuesIsNone,
                    expect: true,
                },
                Check {
                    scenario: "config ports default to none",
                    input: OptionalField::ConfigPortsIsNone,
                    expect: true,
                },
                Check {
                    scenario: "config ports service type defaults to none",
                    input: OptionalField::ConfigPortsServiceTypeIsNone,
                    expect: true,
                },
                Check {
                    scenario: "service nad defaults to none",
                    input: OptionalField::ServiceNadIsNone,
                    expect: true,
                },
                Check {
                    scenario: "daemon set annotations default to none",
                    input: OptionalField::ServiceDaemonSetAnnotationsIsNone,
                    expect: true,
                },
                Check {
                    scenario: "interfaces default to empty",
                    input: OptionalField::InterfacesEmpty,
                    expect: true,
                },
                Check {
                    scenario: "service chain switches default to empty",
                    input: OptionalField::ServiceChainSwitchesEmpty,
                    expect: true,
                },
            ],
            |field| {
                let svc = build();
                match field {
                    OptionalField::HelmValuesIsNone => svc.helm_values.is_none(),
                    OptionalField::ConfigValuesIsNone => svc.config_values.is_none(),
                    OptionalField::ConfigPortsIsNone => svc.config_ports.is_none(),
                    OptionalField::ConfigPortsServiceTypeIsNone => {
                        svc.config_ports_service_type.is_none()
                    }
                    OptionalField::ServiceNadIsNone => svc.service_nad.is_none(),
                    OptionalField::ServiceDaemonSetAnnotationsIsNone => {
                        svc.service_daemon_set_annotations.is_none()
                    }
                    OptionalField::InterfacesEmpty => svc.interfaces.is_empty(),
                    OptionalField::ServiceChainSwitchesEmpty => {
                        svc.service_chain_switches.is_empty()
                    }
                }
            },
        );
    }
}
