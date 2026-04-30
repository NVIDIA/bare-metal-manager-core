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

//! DPF SDK - High-level interface for DPF operations.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::core::ObjectMeta;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::crds::bfbs_generated::{BFB, BfbSpec};
use crate::crds::dpudeployments_generated::{
    DPUDeployment, DpuDeploymentDpus, DpuDeploymentDpusDpuSetStrategy,
    DpuDeploymentDpusDpuSetStrategyType, DpuDeploymentDpusDpuSets,
    DpuDeploymentDpusDpuSetsNodeSelector, DpuDeploymentDpusNodeEffect, DpuDeploymentServiceChains,
    DpuDeploymentServiceChainsSwitches, DpuDeploymentServiceChainsSwitchesPorts,
    DpuDeploymentServiceChainsSwitchesPortsService,
    DpuDeploymentServiceChainsSwitchesPortsServiceInterface,
    DpuDeploymentServiceChainsUpgradePolicy, DpuDeploymentServices, DpuDeploymentServicesDependsOn,
    DpuDeploymentSpec,
};
use crate::crds::dpudevices_generated::{DPUDevice, DpuDeviceSpec};
use crate::crds::dpunodes_generated::{
    DPUNode, DpuNodeDpus, DpuNodeNodeRebootMethod, DpuNodeNodeRebootMethodExternal, DpuNodeSpec,
};
use crate::crds::dpuserviceconfigurations_generated::{
    DPUServiceConfiguration, DpuServiceConfigurationInterfaces,
    DpuServiceConfigurationServiceConfiguration,
    DpuServiceConfigurationServiceConfigurationConfigPorts,
    DpuServiceConfigurationServiceConfigurationConfigPortsPorts,
    DpuServiceConfigurationServiceConfigurationConfigPortsPortsProtocol,
    DpuServiceConfigurationServiceConfigurationConfigPortsServiceType,
    DpuServiceConfigurationServiceConfigurationHelmChart,
    DpuServiceConfigurationServiceConfigurationServiceDaemonSet, DpuServiceConfigurationSpec,
    DpuServiceConfigurationUpgradePolicy,
};
use crate::crds::dpuserviceinterfaces_generated::{
    DPUServiceInterface, DpuServiceInterfaceSpec, DpuServiceInterfaceTemplate,
    DpuServiceInterfaceTemplateSpec, DpuServiceInterfaceTemplateSpecTemplate,
    DpuServiceInterfaceTemplateSpecTemplateMetadata, DpuServiceInterfaceTemplateSpecTemplateSpec,
    DpuServiceInterfaceTemplateSpecTemplateSpecInterfaceType,
    DpuServiceInterfaceTemplateSpecTemplateSpecPf,
    DpuServiceInterfaceTemplateSpecTemplateSpecPhysical,
    DpuServiceInterfaceTemplateSpecTemplateSpecVf,
};
use crate::crds::dpuservicenads_generated::{
    DPUServiceNAD, DpuServiceNadResourceType, DpuServiceNadSpec,
};
use crate::crds::dpuservicetemplates_generated::{
    DPUServiceTemplate, DpuServiceTemplateHelmChart, DpuServiceTemplateHelmChartSource,
    DpuServiceTemplateSpec,
};
use crate::error::DpfError;
use crate::repository::{
    BfbRepository, DpfOperatorConfigRepository, DpuDeploymentRepository, DpuDeviceRepository,
    DpuFlavorRepository, DpuNodeMaintenanceRepository, DpuNodeRepository, DpuRepository,
    DpuServiceConfigurationRepository, DpuServiceNADRepository, DpuServiceTemplateRepository,
    K8sConfigRepository,
};
use crate::types::{
    BmcPasswordProvider, ConfigPortsServiceType, DHCP_SERVER_SERVICE_NAME, DOCA_HBN_SERVICE_NAME,
    DpuDeviceInfo, DpuNodeInfo, DpuPhase, DpuServiceInterfaceTemplateDefinition,
    DpuServiceInterfaceTemplateType, FMDS_SERVICE_NAME, InitDpfResourcesConfig,
    ServiceConfigPortProtocol, ServiceDefinition, ServiceNADResourceType,
};
use crate::watcher::DpuWatcherBuilder;

const SECRET_NAME: &str = "bmc-shared-password";
const BFB_NAME_PREFIX: &str = "bf-bundle";
const DPF_OPERATOR_CONFIG: &str = "dpfoperatorconfig";

pub(crate) const RESTART_ANNOTATION: &str =
    "provisioning.dpu.nvidia.com/dpunode-external-reboot-required";
pub(crate) const HOLD_ANNOTATION: &str = "provisioning.dpu.nvidia.com/wait-for-external-nodeeffect";
/// Provides custom labels for DPF resources.
///
/// Implement this trait to attach caller-specific labels to DPUDevice
/// and DPUNode resources.
pub trait ResourceLabeler: Send + Sync {
    /// Labels to apply to DPUDevice resources on creation.
    fn device_labels(&self, _info: &DpuDeviceInfo) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// Static labels applied to DPUNode resources on creation.
    /// Also used as the `dpu_node_selector` in DPUDeployment
    /// and removed on node deletion.
    fn node_labels(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// Contextual labels applied to DPUNode resources on creation only.
    /// Unlike `node_labels`, these are NOT used for selectors or removal
    /// patches — they carry per-registration metadata (e.g. machine IDs).
    fn node_context_labels(&self, _info: &DpuNodeInfo) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// Optional Kubernetes label selector to scope DPU watches and listings
    /// (e.g. `"app=foo,env=prod"`). Returns `None` by default.
    fn dpu_label_selector(&self) -> Option<String> {
        None
    }
}

/// Default labeler that applies no labels.
pub struct NoLabels;

impl ResourceLabeler for NoLabels {}

/// The main DPF SDK interface.
///
/// This SDK provides high-level operations for managing DPF resources,
/// abstracting away the details of Kubernetes CRD manipulation.
///
/// Trait bounds are on the impl blocks, not the struct, so tests can
/// instantiate `DpfSdk` with a mock that only implements the traits
/// needed by the methods under test.
///
/// Construct via [`DpfSdkBuilder`].
pub struct DpfSdk<R, L = NoLabels> {
    repo: Arc<R>,
    namespace: String,
    labeler: L,
    _bmc_refresh_guard: Option<tokio_util::sync::DropGuard>,
}

impl<R, L> DpfSdk<R, L> {
    /// Get the namespace this SDK operates in.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get a reference to the repository.
    pub fn repo(&self) -> &Arc<R> {
        &self.repo
    }
}

/// Builder for [`DpfSdk`].
pub struct DpfSdkBuilder<'a, R, P, L = NoLabels> {
    repo: R,
    namespace: String,
    labeler: L,
    bmc_password_provider: P,
    bmc_password_refresh_interval: Option<Duration>,
    join_set: Option<&'a mut tokio::task::JoinSet<()>>,
}

impl<R, P> DpfSdkBuilder<'_, R, P> {
    pub fn new(repo: R, namespace: impl Into<String>, bmc_password_provider: P) -> Self {
        DpfSdkBuilder {
            repo,
            namespace: namespace.into(),
            labeler: NoLabels,
            bmc_password_provider,
            bmc_password_refresh_interval: None,
            join_set: None,
        }
    }
}

impl<'a, R, P, L> DpfSdkBuilder<'a, R, P, L> {
    // enables custom labels to be applied to the DPUDevice and DPUNode resources.
    pub fn with_labeler<L2>(self, labeler: L2) -> DpfSdkBuilder<'a, R, P, L2> {
        DpfSdkBuilder {
            repo: self.repo,
            namespace: self.namespace,
            labeler,
            bmc_password_provider: self.bmc_password_provider,
            bmc_password_refresh_interval: self.bmc_password_refresh_interval,
            join_set: self.join_set,
        }
    }

    // enables background refresh of the BMC password.
    pub fn with_bmc_password_refresh_interval(mut self, interval: Duration) -> Self {
        self.bmc_password_refresh_interval = Some(interval);
        self
    }

    /// Spawn background tasks into the provided `JoinSet` instead of
    /// via `tokio::spawn`. Use this in production to join all background
    /// tasks via a single `JoinSet` to catch panics.
    pub fn with_join_set(mut self, join_set: &'a mut tokio::task::JoinSet<()>) -> Self {
        self.join_set = Some(join_set);
        self
    }
}

impl<R, P, L> DpfSdkBuilder<'_, R, P, L>
where
    R: K8sConfigRepository + 'static,
    P: BmcPasswordProvider + 'static,
{
    /// Fetch password, write the K8s BMC secret, spawn refresh task,
    /// and return the constructed SDK.
    async fn init_secret_and_task(self) -> Result<DpfSdk<R, L>, DpfError> {
        let repo = Arc::new(self.repo);
        let namespace = self.namespace;
        let provider = self.bmc_password_provider;

        let password = provider.get_bmc_password().await?;
        write_bmc_secret::<R>(&repo, &namespace, &password).await?;

        let guard = if let Some(interval) = self.bmc_password_refresh_interval {
            Some(spawn_bmc_refresh(
                repo.clone(),
                namespace.clone(),
                provider,
                password,
                interval,
                self.join_set,
            )?)
        } else {
            None
        };

        Ok(DpfSdk {
            repo,
            namespace,
            labeler: self.labeler,
            _bmc_refresh_guard: guard,
        })
    }

    /// Consume the builder, create the K8s BMC secret and optionally
    /// spawn a background refresh task. Does not create DPF CRDs.
    pub async fn build_without_resources(self) -> Result<DpfSdk<R, L>, DpfError> {
        self.init_secret_and_task().await
    }
}

impl<R, P, L> DpfSdkBuilder<'_, R, P, L>
where
    R: BfbRepository
        + DpuFlavorRepository
        + DpuDeploymentRepository
        + DpuServiceTemplateRepository
        + DpuServiceConfigurationRepository
        + DpuServiceNADRepository
        + crate::repository::DpuServiceInterfaceRepository
        + K8sConfigRepository
        + DpfOperatorConfigRepository
        + 'static,
    P: BmcPasswordProvider + 'static,
    L: ResourceLabeler,
{
    /// Consume the builder, create the K8s BMC secret, create all
    /// initialization CRDs, and optionally spawn a background refresh task.
    pub async fn initialize(
        self,
        config: &InitDpfResourcesConfig,
    ) -> Result<DpfSdk<R, L>, DpfError> {
        let sdk = self.init_secret_and_task().await?;
        sdk.create_initialization_objects(config).await?;
        Ok(sdk)
    }
}

async fn write_bmc_secret<R: K8sConfigRepository>(
    repo: &R,
    namespace: &str,
    password: &str,
) -> Result<(), DpfError> {
    let mut data = BTreeMap::new();
    data.insert("password".to_string(), password.as_bytes().to_vec());
    K8sConfigRepository::create_secret(repo, SECRET_NAME, namespace, data).await
}

/// Fetch the current BMC password from the provider and update the K8s
/// secret when it differs from `last_password`. Returns the password
/// value that should be remembered for the next comparison.
async fn refresh_bmc_secret_if_changed<R: K8sConfigRepository>(
    repo: &R,
    namespace: &str,
    provider: &impl BmcPasswordProvider,
    last_password: String,
) -> String {
    match provider.get_bmc_password().await {
        Ok(new_pw) if new_pw != last_password => {
            if let Err(e) = write_bmc_secret::<R>(repo, namespace, &new_pw).await {
                tracing::error!("Failed to refresh BMC secret: {e}");
                last_password
            } else {
                new_pw
            }
        }
        Err(e) => {
            tracing::error!("Failed to read BMC password: {e}");
            last_password
        }
        _ => last_password,
    }
}

// separate function to drop the 'a lifetime from the builder
fn spawn_bmc_refresh<R, P>(
    repo: Arc<R>,
    namespace: String,
    provider: P,
    password: String,
    interval: Duration,
    join_set: Option<&mut tokio::task::JoinSet<()>>,
) -> Result<tokio_util::sync::DropGuard, DpfError>
where
    R: K8sConfigRepository + 'static,
    P: BmcPasswordProvider + 'static,
{
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let guard = cancel_token.clone().drop_guard();
    let task = async move {
        let mut last_password = password;
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        while cancel_token
            .run_until_cancelled(ticker.tick())
            .await
            .is_some()
        {
            last_password =
                refresh_bmc_secret_if_changed(repo.as_ref(), &namespace, &provider, last_password)
                    .await;
        }
    };

    if let Some(js) = join_set {
        js.build_task()
            .name("dpf_bmc_password_refresh")
            .spawn(task)
            .map_err(|e| {
                DpfError::InvalidState(format!("Failed to spawn BMC refresh task: {e}"))
            })?;
    } else {
        tokio::task::Builder::new()
            .name("dpf_bmc_password_refresh")
            .spawn(task)
            .map_err(|e| {
                DpfError::InvalidState(format!("Failed to spawn BMC refresh task: {e}"))
            })?;
    }

    Ok(guard)
}

/// DPUNode CR name: `node-{node_id}`.
/// `node_id` is a compact, stable machine identifier (e.g. `01-02-03-04-05-06`).
/// The DPF CRD limits resource names to 48 characters.
pub fn dpu_node_cr_name(node_id: &str) -> String {
    format!("node-{}", node_id)
}

/// DPUDevice CR name: `device-{device_id}`.
/// The DPF operator uses the DPUDevice CR name verbatim when constructing
/// the DPU CR name (`{dpuNodeName}-{dpuDeviceName}`), so the `device-`
/// prefix produces the expected `node-{node_id}-device-{device_id}` format.
pub fn dpu_device_cr_name(device_id: &str) -> String {
    format!("device-{}", device_id)
}

/// DPU CR name: `node-{node_id}-device-{device_id}`.
/// This matches the DPF operator's naming: `{dpuNodeName}-{dpuDeviceName}`
/// where dpuNodeName = `node-{node_id}` and dpuDeviceName = `device-{device_id}`.
pub fn dpu_cr_name(device_id: &str, node_id: &str) -> String {
    format!(
        "{}-{}",
        dpu_node_cr_name(node_id),
        dpu_device_cr_name(device_id)
    )
}

/// Extract the node ID from a DPUNode CR name by stripping the `node-` prefix.
pub fn node_id_from_dpu_node_cr_name(node_cr_name: &str) -> &str {
    node_cr_name.strip_prefix("node-").unwrap_or(node_cr_name)
}

impl<R, L: ResourceLabeler> DpfSdk<R, L> {
    /// Build a JSON patch that nulls every node label key.
    fn node_label_removal_patch(&self) -> serde_json::Value {
        let nulls: serde_json::Map<String, serde_json::Value> = self
            .labeler
            .node_labels()
            .keys()
            .map(|k| (k.clone(), serde_json::Value::Null))
            .collect();
        json!({ "metadata": { "labels": nulls } })
    }
}

async fn create_bfb<R: BfbRepository>(
    repo: &R,
    namespace: &str,
    bfb_url: &str,
) -> Result<String, DpfError> {
    let bfb_name = format!(
        "{}-{:x}",
        BFB_NAME_PREFIX,
        Sha256::digest(bfb_url.as_bytes())
    );

    let bfb = BFB {
        metadata: ObjectMeta {
            name: Some(bfb_name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: BfbSpec {
            url: bfb_url.to_string(),
            file_name: None,
        },
        status: None,
    };
    match BfbRepository::create(repo, &bfb).await {
        Ok(_) => Ok(bfb_name),
        Err(DpfError::KubeError(kube::Error::Api(ref err)))
            if err.is_already_exists() || err.is_conflict() =>
        {
            tracing::debug!(bfb = %bfb_name, "BFB already exists, reusing");
            Ok(bfb_name)
        }
        Err(e) => Err(e),
    }
}

// DPU flavor is immutable. You should never add any parameter here.
async fn create_dpu_flavor<R: DpuFlavorRepository>(
    repo: &R,
    namespace: &str,
    default_flavor_name: &str,
) -> Result<(), DpfError> {
    let flavor = crate::flavor::default_flavor(namespace, default_flavor_name);

    match DpuFlavorRepository::create(repo, &flavor).await {
        Ok(_) => Ok(()),
        Err(DpfError::KubeError(kube::Error::Api(ref err)))
            if err.is_already_exists() || err.is_conflict() =>
        {
            let existing = DpuFlavorRepository::get(repo, default_flavor_name, namespace).await?;
            if existing
                .as_ref()
                .is_some_and(|f| f.metadata.deletion_timestamp.is_some())
            {
                return Err(DpfError::InvalidState(format!(
                    "DPUFlavor {default_flavor_name} is being deleted (has deletionTimestamp); \
                     cannot re-create until the old resource is fully removed",
                )));
            }
            tracing::debug!("DPU flavor already exists");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub fn build_service_template(svc: &ServiceDefinition, namespace: &str) -> DPUServiceTemplate {
    let helm_values: Option<BTreeMap<String, serde_json::Value>> =
        svc.helm_values.as_ref().and_then(|v| {
            v.as_object()
                .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        });

    DPUServiceTemplate {
        metadata: ObjectMeta {
            name: Some(svc.name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuServiceTemplateSpec {
            deployment_service_name: svc.name.clone(),
            helm_chart: DpuServiceTemplateHelmChart {
                source: DpuServiceTemplateHelmChartSource {
                    chart: Some(svc.helm_chart.clone()),
                    path: None,
                    release_name: None,
                    repo_url: svc.helm_repo_url.clone(),
                    version: svc.helm_version.clone(),
                },
                values: helm_values,
            },
            resource_requirements: None,
        },
        status: None,
    }
}

pub fn build_service_configuration(
    svc: &ServiceDefinition,
    namespace: &str,
) -> DPUServiceConfiguration {
    let interfaces: Vec<DpuServiceConfigurationInterfaces> = svc
        .interfaces
        .iter()
        .map(|i| DpuServiceConfigurationInterfaces {
            name: i.name.clone(),
            network: i.network.clone(),
            virtual_network: None,
        })
        .collect();

    let config_ports_crd = svc.config_ports.as_ref().and_then(|ports| {
        svc.config_ports_service_type.map(|st| {
            DpuServiceConfigurationServiceConfigurationConfigPorts {
                ports: ports
                    .iter()
                    .map(|p| DpuServiceConfigurationServiceConfigurationConfigPortsPorts {
                        name: p.name.clone(),
                        node_port: p.node_port,
                        port: p.port,
                        protocol: match p.protocol {
                            ServiceConfigPortProtocol::Tcp => {
                                DpuServiceConfigurationServiceConfigurationConfigPortsPortsProtocol::Tcp
                            }
                            ServiceConfigPortProtocol::Udp => {
                                DpuServiceConfigurationServiceConfigurationConfigPortsPortsProtocol::Udp
                            }
                        },
                    })
                    .collect(),
                service_type: match st {
                    ConfigPortsServiceType::NodePort => {
                        DpuServiceConfigurationServiceConfigurationConfigPortsServiceType::NodePort
                    }
                    ConfigPortsServiceType::ClusterIp => {
                        DpuServiceConfigurationServiceConfigurationConfigPortsServiceType::ClusterIp
                    }
                    ConfigPortsServiceType::None => {
                        DpuServiceConfigurationServiceConfigurationConfigPortsServiceType::None
                    }
                },
            }
        })
    });

    let helm_chart_config = svc.config_values.as_ref().and_then(|v| {
        v.as_object().map(|obj| {
            let values: BTreeMap<String, serde_json::Value> =
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            DpuServiceConfigurationServiceConfigurationHelmChart {
                values: Some(values),
            }
        })
    });

    let service_daemon_set = svc.service_daemon_set_annotations.as_ref().map(|annos| {
        DpuServiceConfigurationServiceConfigurationServiceDaemonSet {
            annotations: Some(annos.clone()),
            labels: None,
            resources: None,
            update_strategy: None,
        }
    });

    let service_configuration = if config_ports_crd.is_some()
        || helm_chart_config.is_some()
        || service_daemon_set.is_some()
    {
        Some(DpuServiceConfigurationServiceConfiguration {
            config_ports: config_ports_crd,
            deploy_in_cluster: None,
            helm_chart: helm_chart_config,
            service_daemon_set,
        })
    } else {
        None
    };

    DPUServiceConfiguration {
        metadata: ObjectMeta {
            name: Some(svc.name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuServiceConfigurationSpec {
            deployment_service_name: svc.name.clone(),
            interfaces: if interfaces.is_empty() {
                None
            } else {
                Some(interfaces)
            },
            service_configuration,
            upgrade_policy: DpuServiceConfigurationUpgradePolicy {
                apply_node_effect: Some(false),
            },
        },
    }
}

pub fn build_service_nad(svc: &ServiceDefinition, namespace: &str) -> Option<DPUServiceNAD> {
    svc.service_nad.as_ref().map(|service_nad| DPUServiceNAD {
        metadata: ObjectMeta {
            name: Some(service_nad.name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuServiceNadSpec {
            bridge: service_nad.bridge.clone(),
            chained_cn_is: None,
            ipam: service_nad.ipam,
            metadata: None,
            resource_type: match service_nad.resource_type {
                ServiceNADResourceType::Sf => DpuServiceNadResourceType::Sf,
                ServiceNADResourceType::Vf => DpuServiceNadResourceType::Vf,
                ServiceNADResourceType::Veth => DpuServiceNadResourceType::Veth,
            },
            service_mtu: service_nad.mtu,
        },
        status: None,
    })
}

pub fn build_deployment<L: ResourceLabeler>(
    services: &[ServiceDefinition],
    deployment_name: &str,
    bfb_name: &str,
    flavor_name: &str,
    namespace: &str,
    labeler: &L,
    interfaces: &[DpuServiceInterfaceTemplateDefinition],
) -> DPUDeployment {
    let services_map: BTreeMap<String, DpuDeploymentServices> = services
        .iter()
        .map(|svc| {
            (
                svc.name.clone(),
                DpuDeploymentServices {
                    depends_on: if svc.name == "carbide-dpu-agent" {
                        Some(vec![
                            DpuDeploymentServicesDependsOn {
                                name: DHCP_SERVER_SERVICE_NAME.to_string(),
                            },
                            DpuDeploymentServicesDependsOn {
                                name: FMDS_SERVICE_NAME.to_string(),
                            },
                            DpuDeploymentServicesDependsOn {
                                name: DOCA_HBN_SERVICE_NAME.to_string(),
                            },
                        ])
                    } else {
                        None
                    },
                    service_configuration: Some(svc.name.clone()),
                    service_template: Some(svc.name.clone()),
                },
            )
        })
        .collect();

    let mut all_switches = Vec::new();
    for iface in interfaces {
        let Some(chained_svc_if) = iface.chained_svc_if.as_ref() else {
            continue;
        };

        let mut ports = vec![DpuDeploymentServiceChainsSwitchesPorts {
            service_interface: Some(DpuDeploymentServiceChainsSwitchesPortsServiceInterface {
                match_labels: BTreeMap::from([("interface".to_string(), iface.name.clone())]),
                ipam: None,
            }),
            service: None,
        }];

        for (service_name, chain_ifname) in chained_svc_if {
            ports.push(DpuDeploymentServiceChainsSwitchesPorts {
                service_interface: None,
                service: Some(DpuDeploymentServiceChainsSwitchesPortsService {
                    name: service_name.clone(),
                    interface: chain_ifname.clone(),
                    ipam: None,
                }),
            });
        }

        all_switches.push(DpuDeploymentServiceChainsSwitches {
            ports,
            service_mtu: None,
        });
    }

    let service_chains = if all_switches.is_empty() {
        None
    } else {
        Some(DpuDeploymentServiceChains {
            switches: all_switches,
            upgrade_policy: DpuDeploymentServiceChainsUpgradePolicy {
                apply_node_effect: Some(false),
            },
        })
    };

    let mut node_labels = BTreeMap::from([(
        "feature.node.kubernetes.io/dpu-enabled".to_string(),
        "true".to_string(),
    )]);
    for (k, v) in labeler.node_labels() {
        node_labels.insert(k, v);
    }

    DPUDeployment {
        metadata: ObjectMeta {
            name: Some(deployment_name.to_string()),
            namespace: Some(namespace.to_string()),
            annotations: Some(BTreeMap::from([(
                "svc.dpu.nvidia.com/dpudeployment-skip-chain-requestor".to_string(),
                "".to_string(),
            )])),
            ..Default::default()
        },
        spec: DpuDeploymentSpec {
            dpus: DpuDeploymentDpus {
                bfb: bfb_name.to_string(),
                dpu_sets: Some(vec![DpuDeploymentDpusDpuSets {
                    dpu_annotations: None,
                    dpu_selector: None,
                    name_suffix: "default".to_string(),
                    node_selector: Some(DpuDeploymentDpusDpuSetsNodeSelector {
                        match_expressions: None,
                        match_labels: Some(node_labels),
                    }),
                }]),
                flavor: flavor_name.to_string(),
                node_effect: Some(DpuDeploymentDpusNodeEffect {
                    custom_action: None,
                    custom_label: None,
                    drain: None,
                    force: Some(false),
                    hold: Some(true),
                    no_effect: None,
                    taint: None,
                }),
                dpu_set_strategy: Some(DpuDeploymentDpusDpuSetStrategy {
                    rolling_update: None,
                    r#type: Some(DpuDeploymentDpusDpuSetStrategyType::OnDelete),
                }),
            },
            revision_history_limit: None,
            service_chains,
            services: services_map,
        },
        status: None,
    }
}

pub fn build_dpu_interfaces_vec() -> Vec<DpuServiceInterfaceTemplateDefinition> {
    let interfaces: Vec<DpuServiceInterfaceTemplateDefinition> = vec![
        DpuServiceInterfaceTemplateDefinition {
            name: "p0".into(),
            iface_type: DpuServiceInterfaceTemplateType::Physical,
            pf_id: 0,
            vf_id: 0,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "p0_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0hpf".into(),
            iface_type: DpuServiceInterfaceTemplateType::Pf,
            pf_id: 0,
            vf_id: 0,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0hpf_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0hpf_if".into()),
                (FMDS_SERVICE_NAME.into(), "f_pf0hpf_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf0".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 0,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf0_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf0_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf1".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 1,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf1_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf1_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf2".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 2,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf2_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf2_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf3".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 3,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf3_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf3_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf4".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 4,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf4_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf4_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf5".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 5,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf5_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf5_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf6".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 6,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf6_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf6_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf7".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 7,
            chained_svc_if: Some(vec![
                (DOCA_HBN_SERVICE_NAME.into(), "pf0vf7_if".into()),
                (DHCP_SERVER_SERVICE_NAME.into(), "d_pf0vf7_if".into()),
            ]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf8".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 8,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf8_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf9".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 9,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf9_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf10".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 10,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf10_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf11".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 11,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf11_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf12".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 12,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf12_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf0vf13".into(),
            iface_type: DpuServiceInterfaceTemplateType::Vf,
            pf_id: 0,
            vf_id: 13,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf0vf13_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "p1".into(),
            iface_type: DpuServiceInterfaceTemplateType::Physical,
            pf_id: 1,
            vf_id: 0,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "p1_if".into())]),
        },
        DpuServiceInterfaceTemplateDefinition {
            name: "pf1hpf".into(),
            iface_type: DpuServiceInterfaceTemplateType::Pf,
            pf_id: 1,
            vf_id: 0,
            chained_svc_if: Some(vec![(DOCA_HBN_SERVICE_NAME.into(), "pf1hpf_if".into())]),
        },
    ];
    interfaces
}

/// Build a single `DPUServiceInterface` CR from a template definition.
pub fn build_service_interface(
    iface: &DpuServiceInterfaceTemplateDefinition,
    namespace: &str,
) -> DPUServiceInterface {
    let (interface_type, physical, pf, vf) = match iface.iface_type {
        DpuServiceInterfaceTemplateType::Physical => (
            DpuServiceInterfaceTemplateSpecTemplateSpecInterfaceType::Physical,
            Some(DpuServiceInterfaceTemplateSpecTemplateSpecPhysical {
                interface_name: iface.name.clone(),
            }),
            None,
            None,
        ),
        DpuServiceInterfaceTemplateType::Pf => (
            DpuServiceInterfaceTemplateSpecTemplateSpecInterfaceType::Pf,
            None,
            Some(DpuServiceInterfaceTemplateSpecTemplateSpecPf {
                pf_id: iface.pf_id,
                virtual_network: None,
            }),
            None,
        ),
        DpuServiceInterfaceTemplateType::Vf => (
            DpuServiceInterfaceTemplateSpecTemplateSpecInterfaceType::Vf,
            None,
            None,
            Some(DpuServiceInterfaceTemplateSpecTemplateSpecVf {
                parent_interface_ref: Some(if iface.pf_id == 0 {
                    "p0".to_string()
                } else {
                    "p1".to_string()
                }),
                pf_id: iface.pf_id,
                vf_id: iface.vf_id,
                virtual_network: None,
            }),
        ),
        _ => unimplemented!("interface type not supported"),
    };

    let mut cr = DPUServiceInterface::new(
        &iface.name,
        DpuServiceInterfaceSpec {
            cluster_selector: None,
            template: DpuServiceInterfaceTemplate {
                metadata: None,
                spec: DpuServiceInterfaceTemplateSpec {
                    node_selector: None,
                    template: DpuServiceInterfaceTemplateSpecTemplate {
                        metadata: Some(DpuServiceInterfaceTemplateSpecTemplateMetadata {
                            annotations: None,
                            labels: Some(std::collections::BTreeMap::from([(
                                "interface".to_string(),
                                iface.name.clone(),
                            )])),
                        }),
                        spec: DpuServiceInterfaceTemplateSpecTemplateSpec {
                            interface_type,
                            node: None,
                            ovn: None,
                            pf,
                            physical,
                            service: None,
                            vf,
                            vlan: None,
                        },
                    },
                },
            },
        },
    );
    cr.metadata = ObjectMeta {
        name: cr.metadata.name.clone(),
        namespace: Some(namespace.to_string()),
        ..Default::default()
    };
    cr
}

/// Build each standard DPU service interface template and apply it to the repository in one pass.
pub async fn apply_service_interface_templates<
    R: crate::repository::DpuServiceInterfaceRepository,
>(
    repo: &R,
    namespace: &str,
    interfaces: &[DpuServiceInterfaceTemplateDefinition],
) -> Result<(), crate::error::DpfError> {
    for iface in interfaces {
        let cr = build_service_interface(iface, namespace);
        crate::repository::DpuServiceInterfaceRepository::apply(repo, &cr).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_flavor_services_and_deployment<
    R: DpuServiceTemplateRepository
        + DpuServiceConfigurationRepository
        + DpuDeploymentRepository
        + DpuFlavorRepository
        + DpuServiceNADRepository
        + crate::repository::DpuServiceInterfaceRepository,
    L: ResourceLabeler,
>(
    repo: &R,
    namespace: &str,
    labeler: &L,
    services: &[ServiceDefinition],
    deployment_name: &str,
    bfb_name: &str,
    default_flavor_name: &str,
) -> Result<(), DpfError> {
    create_dpu_flavor(repo, namespace, default_flavor_name).await?;

    let interfaces = build_dpu_interfaces_vec();

    apply_service_interface_templates(repo, namespace, &interfaces).await?;

    for svc in services {
        DpuServiceTemplateRepository::apply(repo, &build_service_template(svc, namespace)).await?;
        DpuServiceConfigurationRepository::apply(
            repo,
            &build_service_configuration(svc, namespace),
        )
        .await?;
        if let Some(nad) = build_service_nad(svc, namespace).as_ref() {
            DpuServiceNADRepository::apply(repo, nad).await?;
        }
    }

    let deployment = build_deployment(
        services,
        deployment_name,
        bfb_name,
        default_flavor_name,
        namespace,
        labeler,
        &interfaces,
    );
    DpuDeploymentRepository::apply(repo, &deployment).await?;
    Ok(())
}

impl<
    R: BfbRepository
        + DpuFlavorRepository
        + DpuDeploymentRepository
        + DpuServiceTemplateRepository
        + DpuServiceConfigurationRepository
        + DpuServiceNADRepository
        + crate::repository::DpuServiceInterfaceRepository
        + K8sConfigRepository
        + DpfOperatorConfigRepository,
    L: ResourceLabeler,
> DpfSdk<R, L>
{
    /// Create all initialization CRDs for the "Provision a DPU" flow.
    ///
    /// Order: BFB (BFB controller downloads), DPUFlavor, DPUDeployment with
    /// `dpu_sets` referencing BFB and DPUFlavor. The operator then creates
    /// DPU objects and drives provisioning.
    ///
    /// See: https://docs.nvidia.com/networking/display/dpf2507/component+description#ProvisionaDPU
    pub async fn create_initialization_objects(
        &self,
        config: &InitDpfResourcesConfig,
    ) -> Result<(), DpfError> {
        let bfb_name = create_bfb(&*self.repo, &self.namespace, &config.bfb_url).await?;
        let services = if config.services.is_empty() {
            crate::services::default_services(&crate::services::ServiceRegistryConfig::default())
        } else {
            config.services.clone()
        };
        create_flavor_services_and_deployment(
            &*self.repo,
            &self.namespace,
            &self.labeler,
            &services,
            &config.deployment_name,
            &bfb_name,
            &config.flavor_name,
        )
        .await?;

        if let Some(ref bfcfg) = config.bfcfg_template {
            let data = BTreeMap::from([("BF_CFG_TEMPLATE".to_string(), bfcfg.clone())]);
            K8sConfigRepository::apply_configmap(
                &*self.repo,
                "dpf-bf-cfg-template",
                &self.namespace,
                data,
            )
            .await?;
        } else {
            // Use default bf.cfg. In this case, delete bfCFGTemplateConfigMap from dpfoperatorconfig
            DpfOperatorConfigRepository::patch(
                &*self.repo,
                DPF_OPERATOR_CONFIG,
                &self.namespace,
                serde_json::json!({
                    "spec": {
                        "provisioningController": {
                            "bfCFGTemplateConfigMap": null
                        }
                    }
                }),
            )
            .await?;
        }
        Ok(())
    }
}

impl<R: DpuDeploymentRepository, L> DpfSdk<R, L> {
    /// Update the BFB reference in a DPUDeployment.
    ///
    /// Patches the deployment to point to the given BFB name.
    /// The BFB CR must already exist.
    pub async fn update_deployment_bfb(
        &self,
        deployment_name: &str,
        bfb_name: &str,
    ) -> Result<(), DpfError> {
        let patch = json!({
            "spec": {
                "dpus": {
                    "bfb": bfb_name
                }
            }
        });
        DpuDeploymentRepository::patch(&*self.repo, deployment_name, &self.namespace, patch).await
    }
}

impl<R: DpuDeviceRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Register a new DPU device.
    ///
    /// This operation is idempotent - if the device already exists, it will be
    /// skipped. This handles state machine retries gracefully.
    pub async fn register_dpu_device(&self, info: DpuDeviceInfo) -> Result<(), DpfError> {
        let cr_name = dpu_device_cr_name(&info.device_id);

        let device = DPUDevice {
            metadata: ObjectMeta {
                name: Some(cr_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: {
                    let labels = self.labeler.device_labels(&info);
                    if labels.is_empty() {
                        None
                    } else {
                        Some(labels)
                    }
                },
                ..Default::default()
            },
            spec: DpuDeviceSpec {
                bmc_ip: Some(info.dpu_bmc_ip),
                bmc_port: Some(443),
                number_of_p_fs: Some(1),
                opn: None,
                pf0_name: None,
                psid: None,
                serial_number: info.serial_number,
            },
            status: None,
        };

        match DpuDeviceRepository::create(&*self.repo, &device).await {
            Ok(_) => {
                tracing::info!(device_name = %cr_name, "Created DPU device");
                Ok(())
            }
            Err(DpfError::KubeError(kube::Error::Api(ref err)))
                if err.is_already_exists() || err.is_conflict() =>
            {
                let existing =
                    DpuDeviceRepository::get(&*self.repo, &cr_name, &self.namespace).await?;
                if existing
                    .as_ref()
                    .is_some_and(|d| d.metadata.deletion_timestamp.is_some())
                {
                    return Err(DpfError::InvalidState(format!(
                        "DPUDevice {cr_name} is being deleted (has deletionTimestamp); \
                         cannot re-register until the old resource is fully removed"
                    )));
                }
                tracing::debug!(device_name = %cr_name, "DPU device already exists (concurrent create)");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Delete a DPU device. `dpu_device_name` is the raw device ID (without
    /// the `device-` CR prefix); the SDK applies the prefix internally.
    pub async fn delete_dpu_device(&self, dpu_device_name: &str) -> Result<(), DpfError> {
        let cr_name = dpu_device_cr_name(dpu_device_name);
        DpuDeviceRepository::delete(&*self.repo, &cr_name, &self.namespace).await
    }
}

impl<R: DpuNodeRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Register a new DPU node (host with DPUs).
    ///
    /// This operation is idempotent - if the node already exists, it will be
    /// updated with the new configuration. This is important for multi-DPU setups
    /// where multiple concurrent state machine invocations may call this method.
    pub async fn register_dpu_node(&self, info: DpuNodeInfo) -> Result<(), DpfError> {
        let node_name = dpu_node_cr_name(&info.node_id);

        let node = DPUNode {
            metadata: ObjectMeta {
                name: Some(node_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: {
                    let mut labels = self.labeler.node_labels();
                    labels.extend(self.labeler.node_context_labels(&info));
                    if labels.is_empty() {
                        None
                    } else {
                        Some(labels)
                    }
                },
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(
                    info.device_ids
                        .into_iter()
                        .map(|id| DpuNodeDpus {
                            name: dpu_device_cr_name(&id),
                        })
                        .collect(),
                ),
                node_dms_address: None,
                node_reboot_method: Some(DpuNodeNodeRebootMethod {
                    external: Some(DpuNodeNodeRebootMethodExternal {}),
                    g_noi: None,
                    host_agent: None,
                    script: None,
                }),
            },
            status: None,
        };

        match DpuNodeRepository::create(&*self.repo, &node).await {
            Ok(_) => {
                tracing::info!(node = %node_name, "Created DPU node");
                Ok(())
            }
            Err(DpfError::KubeError(kube::Error::Api(ref err)))
                if err.is_already_exists() || err.is_conflict() =>
            {
                let existing =
                    DpuNodeRepository::get(&*self.repo, &node_name, &self.namespace).await?;
                if existing
                    .as_ref()
                    .is_some_and(|n| n.metadata.deletion_timestamp.is_some())
                {
                    return Err(DpfError::InvalidState(format!(
                        "DPUNode {node_name} is being deleted (has deletionTimestamp); \
                         cannot re-register until the old resource is fully removed"
                    )));
                }
                tracing::debug!(node = %node_name, "DPU node already exists (concurrent create)");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check that a DPUNode's labels contain all entries from the current
    /// labeler's `node_labels()`. Returns `false` when the node exists but
    /// has stale labels (e.g. from a previous label version). Returns `true`
    /// when the node does not exist yet.
    pub async fn verify_node_labels(&self, node_name: &str) -> Result<bool, DpfError> {
        let node = DpuNodeRepository::get(&*self.repo, node_name, &self.namespace).await?;

        let Some(node) = node else {
            return Ok(true);
        };

        let required_labels = self.labeler.node_labels();
        let node_labels = node.metadata.labels.as_ref();

        Ok(required_labels.iter().all(|(key, required_value)| {
            node_labels.is_some_and(|labels| {
                labels
                    .get(key)
                    .is_some_and(|node_value| node_value == required_value)
            })
        }))
    }

    /// Check if reboot is required for a DPU node.
    pub async fn is_reboot_required(&self, node_name: &str) -> Result<bool, DpfError> {
        let node = DpuNodeRepository::get(&*self.repo, node_name, &self.namespace).await?;

        let Some(node) = node else {
            return Err(DpfError::not_found("DPUNode", node_name));
        };

        let Some(annotations) = node.metadata.annotations else {
            return Ok(false);
        };

        Ok(annotations.contains_key(RESTART_ANNOTATION))
    }

    /// Clear the reboot required annotation.
    pub async fn reboot_complete(&self, node_name: &str) -> Result<(), DpfError> {
        let patch = json!({
            "metadata": {
                "annotations": {
                    RESTART_ANNOTATION: null
                }
            }
        });
        DpuNodeRepository::patch(&*self.repo, node_name, &self.namespace, patch).await
    }

    /// Delete a DPU node and associated resources.
    pub async fn delete_dpu_node(&self, node_name: &str) -> Result<(), DpfError> {
        let patch = self.node_label_removal_patch();
        if let Err(e) =
            DpuNodeRepository::patch(&*self.repo, node_name, &self.namespace, patch).await
        {
            tracing::warn!("Failed to remove label from DPU node {}: {}", node_name, e);
        }

        DpuNodeRepository::delete(&*self.repo, node_name, &self.namespace).await
    }
}

impl<R: DpuRepository, L> DpfSdk<R, L> {
    /// Get the DPU phase for a specific DPU.
    pub async fn get_dpu_phase(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<DpuPhase, DpfError> {
        let dpf_id = node_id_from_dpu_node_cr_name(node_name);
        let cr_name = dpu_cr_name(dpu_device_name, dpf_id);
        let dpu = DpuRepository::get(&*self.repo, &cr_name, &self.namespace).await?;

        let Some(dpu) = dpu else {
            return Err(DpfError::not_found("DPU", cr_name));
        };

        let Some(status) = dpu.status else {
            return Err(DpfError::InvalidState(format!(
                "DPU {cr_name} has no status"
            )));
        };

        Ok(DpuPhase::from(status.phase))
    }

    /// Reprovision a DPU by deleting the DPU CR.
    ///
    /// In the DPUDeployment (M4) model the operator creates DPU from DPUDevice; deleting the DPU
    /// CR causes the operator to remove it and create a new DPU (same name) that waits on node
    /// effect. The DPUDevice CR is left in place.
    pub async fn reprovision_dpu(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<(), DpfError> {
        let dpf_id = node_id_from_dpu_node_cr_name(node_name);
        let cr_name = dpu_cr_name(dpu_device_name, dpf_id);
        DpuRepository::delete(&*self.repo, &cr_name, &self.namespace).await
    }
}

impl<R: DpuNodeMaintenanceRepository, L> DpfSdk<R, L> {
    /// Release the hold on a DPU node maintenance.
    /// If the DpuNodeMaintenance CR doesn't exist, this is a no-op
    /// (the hold is effectively already released).
    pub async fn release_maintenance_hold(&self, node_name: &str) -> Result<(), DpfError> {
        let maintenance_name = format!("{}-hold", node_name);
        let patch = json!({
            "metadata": {
                "annotations": {
                    HOLD_ANNOTATION: "false"
                }
            }
        });
        match DpuNodeMaintenanceRepository::patch(
            &*self.repo,
            &maintenance_name,
            &self.namespace,
            patch,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(DpfError::KubeError(kube::Error::Api(ref err))) if err.code == 404 => {
                tracing::debug!(
                    maintenance = %maintenance_name,
                    "DpuNodeMaintenance not found, hold already released"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl<R: DpuRepository + DpuNodeRepository + DpuDeviceRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Force delete a managed host and all its DPU resources.
    ///
    /// In the DPUDeployment (M4) model we remove the DPUNode and DPUDevices so DPF has no record
    /// of the DPU; no status patch to Error. Best-effort: remove controlled label, delete node,
    /// delete all DPU devices.
    ///
    /// `dpu_device_names` contains raw device IDs (without the `device-` CR prefix).
    pub async fn force_delete_host(
        &self,
        node_id: &str,
        dpu_device_names: &[String],
    ) -> Result<(), DpfError> {
        let node_name = &dpu_node_cr_name(node_id);
        let node = DpuNodeRepository::get(&*self.repo, node_name, &self.namespace).await?;

        for name in dpu_device_names {
            let dpu_cr_name = dpu_cr_name(name, node_id);
            let dpu_cr = DpuRepository::get(&*self.repo, &dpu_cr_name, &self.namespace).await?;

            if dpu_cr.is_some() {
                // Move the DPU to the Error phase so the operator stops reconciling it
                // before we drop the DPUNode and DPUDevice CRs below. Best-effort: a
                // failed patch must not block the deletes that follow.
                let patch = json!({ "status": { "phase": "Error" } });
                if let Err(e) =
                    DpuRepository::patch_status(&*self.repo, &dpu_cr_name, &self.namespace, patch)
                        .await
                {
                    tracing::warn!("Failed to patch DPU {} to Error phase: {}", dpu_cr_name, e);
                }
            }
        }

        if let Some(node) = node {
            let dpus = node.spec.dpus.unwrap_or_default();

            let patch = self.node_label_removal_patch();
            if let Err(e) =
                DpuNodeRepository::patch(&*self.repo, node_name, &self.namespace, patch).await
            {
                tracing::warn!("Failed to remove label from DPU node {}: {}", node_name, e);
            }

            if let Err(e) = DpuNodeRepository::delete(&*self.repo, node_name, &self.namespace).await
            {
                tracing::warn!("Failed to delete DPU node {}: {}", node_name, e);
            }

            // dpus[].name already has the device- prefix (set by register_dpu_node)
            for dpu in &dpus {
                if let Err(e) =
                    DpuDeviceRepository::delete(&*self.repo, &dpu.name, &self.namespace).await
                {
                    tracing::warn!("Failed to delete DPU device {}: {}", dpu.name, e);
                }
            }
        } else {
            tracing::info!(
                "DPU node {} not found, trying to delete DPU devices",
                node_name
            );
        }

        for name in dpu_device_names {
            let cr_name = dpu_device_cr_name(name);
            if let Err(e) =
                DpuDeviceRepository::delete(&*self.repo, &cr_name, &self.namespace).await
            {
                tracing::warn!("Failed to delete DPU device {}: {}", cr_name, e);
            }
        }

        Ok(())
    }

    /// Force delete a single DPU and its device.
    ///
    /// In M4 we delete the DPU CR and DPUDevice; no status patch to Error.
    /// `dpu_device_name` is the raw device ID (without the `device-` CR prefix).
    pub async fn force_delete_dpu(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<(), DpfError> {
        let dpf_id = node_id_from_dpu_node_cr_name(node_name);
        let cr_name = dpu_cr_name(dpu_device_name, dpf_id);
        if let Err(e) = DpuRepository::delete(&*self.repo, &cr_name, &self.namespace).await {
            tracing::warn!("Failed to delete DPU {}: {}", cr_name, e);
        }
        let device_cr_name = dpu_device_cr_name(dpu_device_name);
        if let Err(e) =
            DpuDeviceRepository::delete(&*self.repo, &device_cr_name, &self.namespace).await
        {
            tracing::warn!("Failed to delete DPU device {}: {}", device_cr_name, e);
        }
        Ok(())
    }

    /// Force delete a DPU node and all its DPU devices.
    pub async fn force_delete_dpu_node(&self, node_name: &str) -> Result<(), DpfError> {
        let node = DpuNodeRepository::get(&*self.repo, node_name, &self.namespace).await?;
        let dpu_ids: Vec<String> = if let Some(ref n) = node {
            n.spec
                .dpus
                .as_ref()
                .map(|d| d.iter().map(|x| x.name.clone()).collect())
                .unwrap_or_default()
        } else {
            return Ok(());
        };
        let patch = self.node_label_removal_patch();
        if let Err(e) =
            DpuNodeRepository::patch(&*self.repo, node_name, &self.namespace, patch).await
        {
            tracing::warn!("Failed to remove label from DPU node {}: {}", node_name, e);
        }
        if let Err(e) = DpuNodeRepository::delete(&*self.repo, node_name, &self.namespace).await {
            tracing::warn!("Failed to delete DPU node {}: {}", node_name, e);
        }
        for dpu_id in &dpu_ids {
            if let Err(e) = DpuDeviceRepository::delete(&*self.repo, dpu_id, &self.namespace).await
            {
                tracing::warn!("Failed to delete DPU device {}: {}", dpu_id, e);
            }
        }
        Ok(())
    }
}

impl<R: DpuRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Create a watcher builder for DPF events.
    ///
    /// The watcher monitors DPU resources and invokes
    /// callbacks when:
    /// - A DPU's phase changes
    /// - A host reboot is required
    /// - A DPU becomes ready
    /// - Maintenance is needed for a node
    ///
    /// The watcher uses repository traits for all IO, making it testable
    /// with mock repositories.
    ///
    /// Call `.start()` on the returned builder to begin watching.
    pub fn watcher(&self) -> DpuWatcherBuilder<'_, R> {
        let mut builder = DpuWatcherBuilder::new(self.repo.clone(), self.namespace.clone());
        if let Some(selector) = self.labeler.dpu_label_selector() {
            builder = builder.with_label_selector(selector);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::sync::{Arc, RwLock};

    use async_trait::async_trait;
    use kube::Resource;

    use super::*;
    use crate::crds::dpuflavors_generated::DPUFlavor;
    use crate::crds::dpus_generated::DPU;
    use crate::repository::{
        DpuDeviceRepository, DpuFlavorRepository, DpuNodeRepository, DpuRepository,
    };
    use crate::types::{DpuDeviceInfo, DpuNodeInfo};

    fn already_exists_error(name: &str) -> DpfError {
        DpfError::KubeError(kube::Error::Api(Box::new(
            kube::core::Status::failure(&format!("{name} already exists"), "AlreadyExists")
                .with_code(409),
        )))
    }

    const TEST_NAMESPACE: &str = "test-namespace";

    #[derive(Clone, Default)]
    struct SdkMock {
        devices: Arc<RwLock<BTreeMap<String, DPUDevice>>>,
        nodes: Arc<RwLock<BTreeMap<String, DPUNode>>>,
        dpus: Arc<RwLock<BTreeMap<String, DPU>>>,
        flavors: Arc<RwLock<BTreeMap<String, DPUFlavor>>>,
    }

    impl SdkMock {
        fn new() -> Self {
            Self::default()
        }

        fn key<T: Resource>(r: &T) -> String {
            format!(
                "{}/{}",
                r.meta().namespace.as_deref().unwrap_or(""),
                r.meta().name.as_deref().unwrap_or("")
            )
        }

        fn ns_key(ns: &str, name: &str) -> String {
            format!("{}/{}", ns, name)
        }
    }

    #[async_trait]
    impl crate::repository::DpuDeviceRepository for SdkMock {
        async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUDevice>, DpfError> {
            Ok(self
                .devices
                .read()
                .unwrap()
                .get(&Self::ns_key(ns, name))
                .cloned())
        }
        async fn list(&self, ns: &str) -> Result<Vec<DPUDevice>, DpfError> {
            Ok(self
                .devices
                .read()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&format!("{}/", ns)))
                .map(|(_, v)| v.clone())
                .collect())
        }
        async fn create(&self, d: &DPUDevice) -> Result<DPUDevice, DpfError> {
            let key = Self::key(d);
            let mut devices = self.devices.write().unwrap();
            if devices.contains_key(&key) {
                return Err(already_exists_error(d.meta().name.as_deref().unwrap_or("")));
            }
            devices.insert(key, d.clone());
            Ok(d.clone())
        }
        async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
            self.devices
                .write()
                .unwrap()
                .remove(&Self::ns_key(ns, name));
            Ok(())
        }
    }

    #[async_trait]
    impl crate::repository::DpuNodeRepository for SdkMock {
        async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUNode>, DpfError> {
            Ok(self
                .nodes
                .read()
                .unwrap()
                .get(&Self::ns_key(ns, name))
                .cloned())
        }
        async fn list(&self, ns: &str) -> Result<Vec<DPUNode>, DpfError> {
            Ok(self
                .nodes
                .read()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&format!("{}/", ns)))
                .map(|(_, v)| v.clone())
                .collect())
        }
        async fn create(&self, n: &DPUNode) -> Result<DPUNode, DpfError> {
            let key = Self::key(n);
            let mut nodes = self.nodes.write().unwrap();
            if nodes.contains_key(&key) {
                return Err(already_exists_error(n.meta().name.as_deref().unwrap_or("")));
            }
            nodes.insert(key, n.clone());
            Ok(n.clone())
        }
        async fn patch(
            &self,
            name: &str,
            ns: &str,
            patch: serde_json::Value,
        ) -> Result<(), DpfError> {
            if let Some(node) = self.nodes.write().unwrap().get_mut(&Self::ns_key(ns, name)) {
                if let Some(annos) = patch
                    .pointer("/metadata/annotations")
                    .and_then(|v| v.as_object())
                {
                    let node_annos = node.metadata.annotations.get_or_insert_with(BTreeMap::new);
                    for (k, v) in annos {
                        if v.is_null() {
                            node_annos.remove(k);
                        } else if let Some(s) = v.as_str() {
                            node_annos.insert(k.clone(), s.to_string());
                        }
                    }
                }
                if let Some(labels) = patch
                    .pointer("/metadata/labels")
                    .and_then(|v| v.as_object())
                {
                    let node_labels = node.metadata.labels.get_or_insert_with(BTreeMap::new);
                    for (k, v) in labels {
                        if v.is_null() {
                            node_labels.remove(k);
                        } else if let Some(s) = v.as_str() {
                            node_labels.insert(k.clone(), s.to_string());
                        }
                    }
                }
            }
            Ok(())
        }
        async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
            self.nodes.write().unwrap().remove(&Self::ns_key(ns, name));
            Ok(())
        }
    }

    #[async_trait]
    impl crate::repository::DpuRepository for SdkMock {
        async fn get(&self, name: &str, ns: &str) -> Result<Option<DPU>, DpfError> {
            Ok(self
                .dpus
                .read()
                .unwrap()
                .get(&Self::ns_key(ns, name))
                .cloned())
        }
        async fn list(
            &self,
            ns: &str,
            _label_selector: Option<&str>,
        ) -> Result<Vec<DPU>, DpfError> {
            Ok(self
                .dpus
                .read()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&format!("{}/", ns)))
                .map(|(_, v)| v.clone())
                .collect())
        }
        async fn patch_status(
            &self,
            _name: &str,
            _ns: &str,
            _patch: serde_json::Value,
        ) -> Result<(), DpfError> {
            Ok(())
        }
        async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
            self.dpus.write().unwrap().remove(&Self::ns_key(ns, name));
            Ok(())
        }
        fn watch<F, Fut>(
            &self,
            _ns: &str,
            _label_selector: Option<&str>,
            _handler: F,
        ) -> impl Future<Output = ()> + Send + 'static
        where
            F: Fn(Arc<DPU>) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
        {
            futures::future::pending()
        }
    }

    #[async_trait]
    impl crate::repository::K8sConfigRepository for SdkMock {
        async fn get_configmap(
            &self,
            _name: &str,
            _ns: &str,
        ) -> Result<Option<BTreeMap<String, String>>, DpfError> {
            Ok(None)
        }
        async fn apply_configmap(
            &self,
            _name: &str,
            _ns: &str,
            _data: BTreeMap<String, String>,
        ) -> Result<(), DpfError> {
            Ok(())
        }
        async fn get_secret(
            &self,
            _name: &str,
            _ns: &str,
        ) -> Result<Option<BTreeMap<String, Vec<u8>>>, DpfError> {
            Ok(None)
        }
        async fn create_secret(
            &self,
            _name: &str,
            _ns: &str,
            _data: BTreeMap<String, Vec<u8>>,
        ) -> Result<(), DpfError> {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::repository::DpfOperatorConfigRepository for SdkMock {
        async fn patch(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
            Ok(())
        }
    }

    #[async_trait]
    impl DpuFlavorRepository for SdkMock {
        async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUFlavor>, DpfError> {
            Ok(self
                .flavors
                .read()
                .unwrap()
                .get(&Self::ns_key(ns, name))
                .cloned())
        }
        async fn create(&self, f: &DPUFlavor) -> Result<DPUFlavor, DpfError> {
            let key = Self::key(f);
            let mut flavors = self.flavors.write().unwrap();
            if flavors.contains_key(&key) {
                return Err(already_exists_error(f.meta().name.as_deref().unwrap_or("")));
            }
            flavors.insert(key, f.clone());
            Ok(f.clone())
        }
    }

    #[tokio::test]
    async fn test_register_dpu_device() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };

        sdk.register_dpu_device(info).await.unwrap();

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].spec.serial_number, "SN123456");
    }

    #[tokio::test]
    async fn test_register_dpu_node() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string(), "dpu-002".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].metadata.name, Some("node-host-001".to_string()));
        assert_eq!(nodes[0].spec.dpus.as_ref().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_delete_dpu_device() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };

        sdk.register_dpu_device(info).await.unwrap();

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(devices.len(), 1);

        sdk.delete_dpu_device("dpu-001").await.unwrap();

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(devices.len(), 0);
    }

    #[tokio::test]
    async fn test_delete_dpu_node() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);

        sdk.delete_dpu_node("node-host-001").await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 0);
    }

    struct TestLabeler;

    impl ResourceLabeler for TestLabeler {
        fn device_labels(&self, info: &DpuDeviceInfo) -> BTreeMap<String, String> {
            BTreeMap::from([
                ("test/device".to_string(), "true".to_string()),
                ("test/host-bmc-ip".to_string(), info.host_bmc_ip.clone()),
                (
                    "test/host-machine-id".to_string(),
                    info.host_machine_id.clone(),
                ),
                (
                    "test/dpu-machine-id".to_string(),
                    info.dpu_machine_id.clone(),
                ),
            ])
        }

        fn node_labels(&self) -> BTreeMap<String, String> {
            BTreeMap::from([("test/node".to_string(), "true".to_string())])
        }

        fn node_context_labels(&self, info: &DpuNodeInfo) -> BTreeMap<String, String> {
            BTreeMap::from([(
                "test/host-machine-id".to_string(),
                info.host_machine_id.clone(),
            )])
        }
    }

    #[tokio::test]
    async fn test_dpu_device_info_labels() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };

        sdk.register_dpu_device(info).await.unwrap();

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        let device = &devices[0];
        let labels = device.metadata.labels.as_ref().unwrap();

        assert_eq!(labels.get("test/device"), Some(&"true".to_string()));
        assert_eq!(
            labels.get("test/host-bmc-ip"),
            Some(&"10.0.0.1".to_string())
        );
        assert_eq!(
            labels.get("test/host-machine-id"),
            Some(&"host-aaa".to_string())
        );
        assert_eq!(
            labels.get("test/dpu-machine-id"),
            Some(&"dpu-bbb".to_string())
        );
    }

    #[tokio::test]
    async fn test_dpu_device_no_labels_without_labeler() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };

        sdk.register_dpu_device(info).await.unwrap();

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        let device = &devices[0];
        assert!(device.metadata.labels.is_none());
    }

    #[tokio::test]
    async fn test_dpu_node_labels() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        let node = &nodes[0];
        let labels = node.metadata.labels.as_ref().unwrap();

        assert_eq!(labels.get("test/node"), Some(&"true".to_string()));
        assert_eq!(
            labels.get("test/host-machine-id"),
            Some(&"host-aaa".to_string()),
            "contextual label from node_context_labels should be merged"
        );
    }

    #[tokio::test]
    async fn test_dpu_node_no_labels_without_labeler() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        let node = &nodes[0];
        assert!(node.metadata.labels.is_none());
    }

    #[tokio::test]
    async fn test_node_label_removal_patch_contains_labeler_keys() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        let patch = sdk.node_label_removal_patch();
        let labels = patch
            .pointer("/metadata/labels")
            .unwrap()
            .as_object()
            .unwrap();

        assert!(labels.contains_key("test/node"));
        assert!(labels["test/node"].is_null());
    }

    #[tokio::test]
    async fn test_node_label_removal_patch_empty_without_labeler() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let patch = sdk.node_label_removal_patch();
        let labels = patch
            .pointer("/metadata/labels")
            .unwrap()
            .as_object()
            .unwrap();

        assert!(labels.is_empty());
    }

    #[tokio::test]
    async fn test_reprovision_dpu_deletes_dpu_not_device() {
        use kube::core::ObjectMeta;

        use crate::crds::dpus_generated::{DpuSpec, DpuStatus, DpuStatusPhase};

        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let device_info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };
        sdk.register_dpu_device(device_info).await.unwrap();

        let dpu_name = "node-dpu-001-device-dpu-001";
        let dpu = DPU {
            metadata: ObjectMeta {
                name: Some(dpu_name.to_string()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: DpuSpec {
                bfb: "bf-bundle".to_string(),
                bmc_ip: None,
                cluster: None,
                dpu_device_name: "dpu-001".to_string(),
                dpu_flavor: Some(crate::flavor::DEFAULT_FLAVOR_NAME.to_string()),
                dpu_node_name: "node-dpu-001".to_string(),
                node_effect: None,
                pci_address: None,
                serial_number: "SN123".to_string(),
            },
            status: Some(DpuStatus {
                phase: DpuStatusPhase::Ready,
                addresses: None,
                bf_cfg_file: None,
                bfb_file: None,
                bfb_version: None,
                conditions: None,
                dpf_version: None,
                dpu_install_interface: None,
                dpu_mode: None,
                firmware: None,
                observed_generation: None,
                pci_device: None,
                post_provisioning_node_effect: None,
                required_reset: None,
            }),
        };
        mock.dpus
            .write()
            .unwrap()
            .insert(format!("{}/{}", TEST_NAMESPACE, dpu_name), dpu);

        sdk.reprovision_dpu("dpu-001", "node-dpu-001")
            .await
            .unwrap();

        let dpus = DpuRepository::list(&mock, TEST_NAMESPACE, None)
            .await
            .unwrap();
        assert_eq!(dpus.len(), 0, "DPU CR should be deleted");

        let devices = DpuDeviceRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(devices.len(), 1, "DPUDevice should remain");
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let mock = SdkMock::new();

        let sdk1 = DpfSdkBuilder::new(mock.clone(), "namespace-1", String::new())
            .build_without_resources()
            .await
            .unwrap();
        let sdk2 = DpfSdkBuilder::new(mock.clone(), "namespace-2", String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info1 = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN111".to_string(),
            host_machine_id: "host-111".to_string(),
            dpu_machine_id: "dpu-111".to_string(),
        };

        let info2 = DpuDeviceInfo {
            device_id: "dpu-002".to_string(),
            dpu_bmc_ip: "10.0.0.20".to_string(),
            host_bmc_ip: "10.0.0.2".to_string(),
            serial_number: "SN222".to_string(),
            host_machine_id: "host-222".to_string(),
            dpu_machine_id: "dpu-222".to_string(),
        };

        sdk1.register_dpu_device(info1).await.unwrap();
        sdk2.register_dpu_device(info2).await.unwrap();

        let devices1 = DpuDeviceRepository::list(&mock, "namespace-1")
            .await
            .unwrap();
        let devices2 = DpuDeviceRepository::list(&mock, "namespace-2")
            .await
            .unwrap();

        assert_eq!(devices1.len(), 1);
        assert_eq!(devices2.len(), 1);
        assert_eq!(devices1[0].spec.serial_number, "SN111");
        assert_eq!(devices2[0].spec.serial_number, "SN222");
    }

    #[derive(Clone, Default)]
    struct SecretTrackingMock {
        secrets_written: Arc<std::sync::Mutex<Vec<String>>>,
        fail_writes: bool,
    }

    #[async_trait]
    impl crate::repository::K8sConfigRepository for SecretTrackingMock {
        async fn get_configmap(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<BTreeMap<String, String>>, DpfError> {
            Ok(None)
        }
        async fn apply_configmap(
            &self,
            _: &str,
            _: &str,
            _: BTreeMap<String, String>,
        ) -> Result<(), DpfError> {
            Ok(())
        }
        async fn get_secret(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<BTreeMap<String, Vec<u8>>>, DpfError> {
            Ok(None)
        }
        async fn create_secret(
            &self,
            _name: &str,
            _ns: &str,
            data: BTreeMap<String, Vec<u8>>,
        ) -> Result<(), DpfError> {
            if self.fail_writes {
                return Err(DpfError::ConfigError("simulated write failure".into()));
            }
            if let Some(pw_bytes) = data.get("password") {
                let pw = String::from_utf8(pw_bytes.clone()).unwrap();
                self.secrets_written.lock().unwrap().push(pw);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl crate::repository::DpfOperatorConfigRepository for SecretTrackingMock {
        async fn patch(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_refresh_writes_secret_when_password_changes() {
        let mock = SecretTrackingMock::default();
        let provider = "new-password".to_string();

        let result =
            refresh_bmc_secret_if_changed(&mock, TEST_NAMESPACE, &provider, "old-password".into())
                .await;

        assert_eq!(result, "new-password");
        assert_eq!(
            mock.secrets_written.lock().unwrap().as_slice(),
            &["new-password"]
        );
    }

    #[tokio::test]
    async fn test_refresh_skips_write_when_password_unchanged() {
        let mock = SecretTrackingMock::default();
        let provider = "same".to_string();

        let result =
            refresh_bmc_secret_if_changed(&mock, TEST_NAMESPACE, &provider, "same".into()).await;

        assert_eq!(result, "same");
        assert!(mock.secrets_written.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_refresh_retains_last_password_on_write_failure() {
        let mock = SecretTrackingMock {
            fail_writes: true,
            ..Default::default()
        };
        let provider = "new-password".to_string();

        let result =
            refresh_bmc_secret_if_changed(&mock, TEST_NAMESPACE, &provider, "old-password".into())
                .await;

        assert_eq!(result, "old-password");
    }

    #[tokio::test]
    async fn test_init_config_defaults() {
        let config = InitDpfResourcesConfig::default();
        assert!(config.bfb_url.is_empty());
        assert_eq!(config.deployment_name, "dpu-deployment");
        assert_eq!(config.flavor_name, crate::flavor::DEFAULT_FLAVOR_NAME);
        assert!(config.services.is_empty());
    }

    #[tokio::test]
    async fn test_init_config_custom() {
        let config = InitDpfResourcesConfig {
            bfb_url: "http://example.com/test.bfb".to_string(),
            deployment_name: "my-deployment".to_string(),
            flavor_name: "my-flavor".to_string(),
            services: vec![],
            bfcfg_template: None,
        };

        assert_eq!(config.bfb_url, "http://example.com/test.bfb");
        assert_eq!(config.deployment_name, "my-deployment");
        assert_eq!(config.flavor_name, "my-flavor");
    }

    fn terminating_timestamp() -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
        )
    }

    #[tokio::test]
    async fn test_register_dpu_device_fails_when_terminating() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let terminating_device = DPUDevice {
            metadata: ObjectMeta {
                name: Some(dpu_device_cr_name("dpu-001")),
                namespace: Some(TEST_NAMESPACE.to_string()),
                deletion_timestamp: Some(terminating_timestamp()),
                ..Default::default()
            },
            spec: DpuDeviceSpec {
                bmc_ip: Some("10.0.0.10".to_string()),
                bmc_port: Some(443),
                number_of_p_fs: Some(1),
                opn: None,
                pf0_name: None,
                psid: None,
                serial_number: "SN123456".to_string(),
            },
            status: None,
        };
        mock.devices
            .write()
            .unwrap()
            .insert(SdkMock::key(&terminating_device), terminating_device);

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };
        let err = sdk.register_dpu_device(info).await.unwrap_err();
        assert!(
            matches!(err, DpfError::InvalidState(_)),
            "expected InvalidState, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_register_dpu_device_ok_when_existing_not_terminating() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let existing_device = DPUDevice {
            metadata: ObjectMeta {
                name: Some(dpu_device_cr_name("dpu-001")),
                namespace: Some(TEST_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: DpuDeviceSpec {
                bmc_ip: Some("10.0.0.10".to_string()),
                bmc_port: Some(443),
                number_of_p_fs: Some(1),
                opn: None,
                pf0_name: None,
                psid: None,
                serial_number: "SN123456".to_string(),
            },
            status: None,
        };
        mock.devices
            .write()
            .unwrap()
            .insert(SdkMock::key(&existing_device), existing_device);

        let info = DpuDeviceInfo {
            device_id: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
            host_machine_id: "host-aaa".to_string(),
            dpu_machine_id: "dpu-bbb".to_string(),
        };
        sdk.register_dpu_device(info).await.unwrap();
    }

    #[tokio::test]
    async fn test_register_dpu_node_fails_when_terminating() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let node_name = dpu_node_cr_name("host-001");
        let terminating_node = DPUNode {
            metadata: ObjectMeta {
                name: Some(node_name.clone()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                deletion_timestamp: Some(terminating_timestamp()),
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&terminating_node), terminating_node);

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };
        let err = sdk.register_dpu_node(info).await.unwrap_err();
        assert!(
            matches!(err, DpfError::InvalidState(_)),
            "expected InvalidState, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_register_dpu_node_ok_when_existing_not_terminating() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let node_name = dpu_node_cr_name("host-001");
        let existing_node = DPUNode {
            metadata: ObjectMeta {
                name: Some(node_name.clone()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&existing_node), existing_node);

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };
        sdk.register_dpu_node(info).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_dpu_flavor_fails_when_terminating() {
        let mock = SdkMock::new();
        let flavor =
            crate::flavor::default_flavor(TEST_NAMESPACE, crate::flavor::DEFAULT_FLAVOR_NAME);
        let mut terminating_flavor = flavor.clone();
        terminating_flavor.metadata.deletion_timestamp = Some(terminating_timestamp());
        mock.flavors
            .write()
            .unwrap()
            .insert(SdkMock::key(&terminating_flavor), terminating_flavor);

        let err = create_dpu_flavor(&mock, TEST_NAMESPACE, crate::flavor::DEFAULT_FLAVOR_NAME)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DpfError::InvalidState(_)),
            "expected InvalidState, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_create_dpu_flavor_ok_when_existing_not_terminating() {
        let mock = SdkMock::new();
        let flavor =
            crate::flavor::default_flavor(TEST_NAMESPACE, crate::flavor::DEFAULT_FLAVOR_NAME);
        mock.flavors
            .write()
            .unwrap()
            .insert(SdkMock::key(&flavor), flavor);

        create_dpu_flavor(&mock, TEST_NAMESPACE, crate::flavor::DEFAULT_FLAVOR_NAME)
            .await
            .unwrap();
    }

    #[derive(Clone, Default)]
    struct BfbMock {
        bfbs: Arc<RwLock<BTreeMap<String, BFB>>>,
    }

    #[async_trait]
    impl crate::repository::BfbRepository for BfbMock {
        async fn get(&self, name: &str, ns: &str) -> Result<Option<BFB>, DpfError> {
            Ok(self
                .bfbs
                .read()
                .unwrap()
                .get(&format!("{ns}/{name}"))
                .cloned())
        }
        async fn list(&self, ns: &str) -> Result<Vec<BFB>, DpfError> {
            let prefix = format!("{ns}/");
            Ok(self
                .bfbs
                .read()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        }
        async fn create(&self, bfb: &BFB) -> Result<BFB, DpfError> {
            let key = format!(
                "{}/{}",
                bfb.meta().namespace.as_deref().unwrap_or(""),
                bfb.meta().name.as_deref().unwrap_or("")
            );
            let mut store = self.bfbs.write().unwrap();
            if store.contains_key(&key) {
                return Err(already_exists_error(
                    bfb.meta().name.as_deref().unwrap_or(""),
                ));
            }
            store.insert(key, bfb.clone());
            Ok(bfb.clone())
        }
        async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
            self.bfbs.write().unwrap().remove(&format!("{ns}/{name}"));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_bfb_deterministic_name() {
        let url = "http://example.com/some.bfb";
        let name1 = create_bfb(&BfbMock::default(), TEST_NAMESPACE, url)
            .await
            .unwrap();
        let name2 = create_bfb(&BfbMock::default(), TEST_NAMESPACE, url)
            .await
            .unwrap();
        assert_eq!(name1, name2, "same URL must produce the same BFB name");
        assert!(name1.starts_with("bf-bundle-"));
    }

    #[tokio::test]
    async fn test_create_bfb_name_valid_k8s() {
        let url = "http://example.com/UPPER_case/special?chars=true&foo=bar#fragment";
        let name = create_bfb(&BfbMock::default(), TEST_NAMESPACE, url)
            .await
            .unwrap();
        assert!(name.len() <= 253, "name length {} exceeds 253", name.len());
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
            "name contains invalid characters: {name}"
        );
        assert!(
            name.chars().next().unwrap().is_ascii_alphanumeric(),
            "name must start with alphanumeric: {name}"
        );
        assert!(
            name.chars().last().unwrap().is_ascii_alphanumeric(),
            "name must end with alphanumeric: {name}"
        );
    }

    #[tokio::test]
    async fn test_create_bfb_different_urls_different_names() {
        let mock = BfbMock::default();
        let name_a = create_bfb(&mock, TEST_NAMESPACE, "http://a.example.com/a.bfb")
            .await
            .unwrap();
        let name_b = create_bfb(&mock, TEST_NAMESPACE, "http://b.example.com/b.bfb")
            .await
            .unwrap();
        assert_ne!(name_a, name_b);
    }

    #[tokio::test]
    async fn test_create_bfb_reuses_existing() {
        let mock = BfbMock::default();
        let url = "http://example.com/reuse.bfb";
        let name1 = create_bfb(&mock, TEST_NAMESPACE, url).await.unwrap();
        let name2 = create_bfb(&mock, TEST_NAMESPACE, url).await.unwrap();
        assert_eq!(name1, name2);
        assert_eq!(
            mock.bfbs.read().unwrap().len(),
            1,
            "only one BFB should exist"
        );
    }

    #[tokio::test]
    async fn test_verify_node_labels_current_labels_returns_true() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuNodeInfo {
            node_id: "host-001".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            device_ids: vec!["dpu-001".to_string()],
            host_machine_id: "host-aaa".to_string(),
        };
        sdk.register_dpu_node(info).await.unwrap();

        assert!(sdk.verify_node_labels("node-host-001").await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_node_labels_missing_node_returns_true() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        assert!(
            sdk.verify_node_labels("node-does-not-exist").await.unwrap(),
            "non-existent node should return true (will be created with current labels)"
        );
    }

    #[tokio::test]
    async fn test_verify_node_labels_stale_labels_returns_false() {
        let mock = SdkMock::new();

        let stale_node = DPUNode {
            metadata: ObjectMeta {
                name: Some("node-host-001".to_string()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                labels: Some(BTreeMap::from([(
                    "old/stale-label".to_string(),
                    "true".to_string(),
                )])),
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&stale_node), stale_node);

        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        assert!(
            !sdk.verify_node_labels("node-host-001").await.unwrap(),
            "node with stale labels should return false"
        );
    }

    #[tokio::test]
    async fn test_verify_node_labels_no_labels_returns_false() {
        let mock = SdkMock::new();

        let bare_node = DPUNode {
            metadata: ObjectMeta {
                name: Some("node-host-001".to_string()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                labels: None,
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&bare_node), bare_node);

        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        assert!(
            !sdk.verify_node_labels("node-host-001").await.unwrap(),
            "node with no labels should return false when labeler expects labels"
        );
    }

    #[tokio::test]
    async fn test_verify_node_labels_superset_returns_true() {
        let mock = SdkMock::new();

        let superset_node = DPUNode {
            metadata: ObjectMeta {
                name: Some("node-host-001".to_string()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                labels: Some(BTreeMap::from([
                    ("test/node".to_string(), "true".to_string()),
                    ("extra/label".to_string(), "extra-value".to_string()),
                ])),
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&superset_node), superset_node);

        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        assert!(
            sdk.verify_node_labels("node-host-001").await.unwrap(),
            "node with a superset of expected labels should return true"
        );
    }

    #[tokio::test]
    async fn test_verify_node_labels_wrong_value_returns_false() {
        let mock = SdkMock::new();

        let wrong_value_node = DPUNode {
            metadata: ObjectMeta {
                name: Some("node-host-001".to_string()),
                namespace: Some(TEST_NAMESPACE.to_string()),
                labels: Some(BTreeMap::from([(
                    "test/node".to_string(),
                    "false".to_string(),
                )])),
                ..Default::default()
            },
            spec: DpuNodeSpec {
                dpus: Some(vec![]),
                node_dms_address: None,
                node_reboot_method: None,
            },
            status: None,
        };
        mock.nodes
            .write()
            .unwrap()
            .insert(SdkMock::key(&wrong_value_node), wrong_value_node);

        let sdk = DpfSdkBuilder::new(mock, TEST_NAMESPACE, String::new())
            .with_labeler(TestLabeler)
            .build_without_resources()
            .await
            .unwrap();

        assert!(
            !sdk.verify_node_labels("node-host-001").await.unwrap(),
            "node with correct key but wrong value should return false"
        );
    }
}
