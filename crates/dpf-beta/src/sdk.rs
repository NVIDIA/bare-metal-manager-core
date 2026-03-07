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

//! DPF SDK - High-level interface for DPF operations.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::core::ObjectMeta;
use serde_json::json;

use crate::crds::bfbs_generated::{BFB, BfbSpec};
use crate::crds::dpudeployments_generated::{
    DPUDeployment, DpuDeploymentDpus, DpuDeploymentDpusDpuSets,
    DpuDeploymentDpusDpuSetsNodeSelector, DpuDeploymentDpusNodeEffect, DpuDeploymentServiceChains,
    DpuDeploymentServiceChainsSwitches, DpuDeploymentServiceChainsSwitchesPorts,
    DpuDeploymentServiceChainsSwitchesPortsService,
    DpuDeploymentServiceChainsSwitchesPortsServiceInterface,
    DpuDeploymentServiceChainsUpgradePolicy, DpuDeploymentServices, DpuDeploymentSpec,
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
use crate::crds::dpuservicetemplates_generated::{
    DPUServiceTemplate, DpuServiceTemplateHelmChart, DpuServiceTemplateHelmChartSource,
    DpuServiceTemplateSpec,
};
use crate::error::DpfError;
use crate::repository::{
    BfbRepository, DpuDeploymentRepository, DpuDeviceRepository, DpuFlavorRepository,
    DpuNodeMaintenanceRepository, DpuNodeRepository, DpuRepository,
    DpuServiceConfigurationRepository, DpuServiceTemplateRepository, K8sConfigRepository,
};
use crate::types::{
    BmcPasswordProvider, ConfigPortsServiceType, DpuDeviceInfo, DpuNodeInfo, DpuPhase,
    InitDpfResourcesConfig, ServiceConfigPortProtocol, ServiceDefinition,
};
use crate::watcher::DpuWatcherBuilder;

const SECRET_NAME: &str = "bmc-shared-password";
const BFB_NAME_PREFIX: &str = "bf-bundle";

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

    /// Labels to apply to DPUNode resources on creation.
    /// Also used as the `dpu_node_selector` in DPUDeployment
    /// and removed on node deletion.
    fn node_labels(&self) -> BTreeMap<String, String> {
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
    _bmc_password_refresh_task: Option<tokio::task::JoinHandle<()>>,
}

impl<R, L> Drop for DpfSdk<R, L> {
    fn drop(&mut self) {
        if let Some(handle) = self._bmc_password_refresh_task.take() {
            handle.abort();
        }
    }
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
pub struct DpfSdkBuilder<R, P, L = NoLabels> {
    repo: R,
    namespace: String,
    labeler: L,
    bmc_password_provider: P,
    bmc_password_refresh_interval: Option<Duration>,
}

impl<R, P> DpfSdkBuilder<R, P> {
    pub fn new(repo: R, namespace: impl Into<String>, bmc_password_provider: P) -> Self {
        DpfSdkBuilder {
            repo,
            namespace: namespace.into(),
            labeler: NoLabels,
            bmc_password_provider,
            bmc_password_refresh_interval: None,
        }
    }
}

impl<R, P, L> DpfSdkBuilder<R, P, L> {
    // enables custom labels to be applied to the DPUDevice and DPUNode resources.
    pub fn with_labeler<L2>(self, labeler: L2) -> DpfSdkBuilder<R, P, L2> {
        DpfSdkBuilder {
            repo: self.repo,
            namespace: self.namespace,
            labeler,
            bmc_password_provider: self.bmc_password_provider,
            bmc_password_refresh_interval: self.bmc_password_refresh_interval,
        }
    }

    // enables background refresh of the BMC password.
    pub fn with_bmc_password_refresh_interval(mut self, interval: Duration) -> Self {
        self.bmc_password_refresh_interval = Some(interval);
        self
    }
}

impl<R, P, L> DpfSdkBuilder<R, P, L>
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

        let refresh_task = self.bmc_password_refresh_interval.map(|interval| {
            let r = repo.clone();
            let ns = namespace.clone();
            tokio::spawn(async move {
                let mut last_password = password;
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // skip the first (immediate) tick since we just wrote the secret
                loop {
                    ticker.tick().await;
                    last_password =
                        refresh_bmc_secret_if_changed(r.as_ref(), &ns, &provider, last_password)
                            .await;
                }
            })
        });

        Ok(DpfSdk {
            repo,
            namespace,
            labeler: self.labeler,
            _bmc_password_refresh_task: refresh_task,
        })
    }

    /// Consume the builder, create the K8s BMC secret and optionally
    /// spawn a background refresh task. Does not create DPF CRDs.
    pub async fn build_without_resources(self) -> Result<DpfSdk<R, L>, DpfError> {
        self.init_secret_and_task().await
    }
}

impl<R, P, L> DpfSdkBuilder<R, P, L>
where
    R: BfbRepository
        + DpuFlavorRepository
        + DpuDeploymentRepository
        + DpuServiceTemplateRepository
        + DpuServiceConfigurationRepository
        + K8sConfigRepository
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

/// DPUNode name used by the DPF operator: `dpu-node-{node_id}`.
/// `node_id` is a stable host identifier (e.g. host machine UUID), not an IP.
pub fn dpu_node_name(node_id: &str) -> String {
    format!("dpu-node-{}", node_id)
}

/// DPU resource name: `dpu-node-{node_id}-{dpu_device_name}`.
pub fn dpu_name(dpu_device_name: &str, node_id: &str) -> String {
    format!("dpu-node-{}-{}", node_id, dpu_device_name)
}

/// Extract the node ID from a DPUNode name by stripping the `dpu-node-` prefix.
pub fn node_id_from_node_name(node_name: &str) -> &str {
    node_name.strip_prefix("dpu-node-").unwrap_or(node_name)
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
    let bfb_name = format!("{}-{}", BFB_NAME_PREFIX, uuid::Uuid::new_v4());
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
    BfbRepository::create(repo, &bfb).await?;
    Ok(bfb_name)
}

async fn create_dpu_flavor<R: DpuFlavorRepository>(
    repo: &R,
    namespace: &str,
) -> Result<(), DpfError> {
    let flavor = crate::flavor::default_flavor(namespace);
    match DpuFlavorRepository::create(repo, &flavor).await {
        Ok(_) => Ok(()),
        Err(DpfError::KubeError(kube::Error::Api(ref err))) if err.is_conflict() => {
            tracing::debug!("DPU flavor already exists");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn create_services_and_deployment<
    R: DpuServiceTemplateRepository + DpuServiceConfigurationRepository + DpuDeploymentRepository,
    L: ResourceLabeler,
>(
    repo: &R,
    namespace: &str,
    labeler: &L,
    services: &[ServiceDefinition],
    deployment_name: &str,
    bfb_name: &str,
) -> Result<(), DpfError> {
    for svc in services {
        let helm_values: Option<BTreeMap<String, serde_json::Value>> =
            svc.helm_values.as_ref().and_then(|v| {
                v.as_object()
                    .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            });

        let template = DPUServiceTemplate {
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
        };
        DpuServiceTemplateRepository::apply(repo, &template).await?;

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

        let config_crd = DPUServiceConfiguration {
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
        };
        DpuServiceConfigurationRepository::apply(repo, &config_crd).await?;
    }

    let mut services_map = BTreeMap::new();
    for svc in services {
        services_map.insert(
            svc.name.clone(),
            DpuDeploymentServices {
                depends_on: None,
                service_configuration: Some(svc.name.clone()),
                service_template: Some(svc.name.clone()),
            },
        );
    }

    let all_switches: Vec<DpuDeploymentServiceChainsSwitches> = services
        .iter()
        .flat_map(|svc| {
            svc.service_chain_switches
                .iter()
                .map(|chain| DpuDeploymentServiceChainsSwitches {
                    ports: vec![
                        DpuDeploymentServiceChainsSwitchesPorts {
                            service_interface: Some(
                                DpuDeploymentServiceChainsSwitchesPortsServiceInterface {
                                    match_labels: BTreeMap::from([(
                                        "interface".to_string(),
                                        chain.physical_interface.clone(),
                                    )]),
                                    ipam: None,
                                },
                            ),
                            service: None,
                        },
                        DpuDeploymentServiceChainsSwitchesPorts {
                            service: Some(DpuDeploymentServiceChainsSwitchesPortsService {
                                name: chain.service_name.clone(),
                                interface: chain.service_interface.clone(),
                                ipam: None,
                            }),
                            service_interface: None,
                        },
                    ],
                    service_mtu: None,
                })
        })
        .collect();

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

    let deployment = DPUDeployment {
        metadata: ObjectMeta {
            name: Some(deployment_name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuDeploymentSpec {
            dpus: DpuDeploymentDpus {
                bfb: bfb_name.to_string(),
                dpu_sets: Some(vec![DpuDeploymentDpusDpuSets {
                    dpu_annotations: None,
                    dpu_selector: None,
                    name_suffix: String::new(),
                    node_selector: {
                        let mut labels = BTreeMap::from([(
                            "feature.node.kubernetes.io/dpu-enabled".to_string(),
                            "true".to_string(),
                        )]);
                        for (k, v) in labeler.node_labels() {
                            labels.insert(k, v);
                        }
                        Some(DpuDeploymentDpusDpuSetsNodeSelector {
                            match_expressions: None,
                            match_labels: Some(labels),
                        })
                    },
                }]),
                flavor: crate::flavor::DPUFLAVOR_NAME.to_string(),
                node_effect: Some(DpuDeploymentDpusNodeEffect {
                    custom_action: None,
                    custom_label: None,
                    drain: None,
                    force: Some(false),
                    hold: Some(true),
                    no_effect: None,
                    taint: None,
                }),
            },
            revision_history_limit: None,
            service_chains,
            services: services_map,
        },
        status: None,
    };

    DpuDeploymentRepository::apply(repo, &deployment).await?;
    Ok(())
}

impl<
    R: BfbRepository
        + DpuFlavorRepository
        + DpuDeploymentRepository
        + DpuServiceTemplateRepository
        + DpuServiceConfigurationRepository
        + K8sConfigRepository,
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
        create_dpu_flavor(&*self.repo, &self.namespace).await?;
        let services = if config.services.is_empty() {
            crate::services::default_services(&crate::services::ServiceRegistryConfig::default())
        } else {
            config.services.clone()
        };
        create_services_and_deployment(
            &*self.repo,
            &self.namespace,
            &self.labeler,
            &services,
            &config.deployment_name,
            &bfb_name,
        )
        .await?;
        if let Some(ref bfcfg) = config.bfcfg_template {
            let data = BTreeMap::from([("BF_CFG_TEMPLATE".to_string(), bfcfg.clone())]);
            K8sConfigRepository::apply_configmap(
                &*self.repo,
                "carbide-dpf-bf-cfg-template",
                &self.namespace,
                data,
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
        let device_name = info.device_name.clone();

        let device = DPUDevice {
            metadata: ObjectMeta {
                name: Some(info.device_name.clone()),
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
                tracing::info!(device_name = %device_name, "Created DPU device");
                Ok(())
            }
            Err(DpfError::KubeError(kube::Error::Api(ref err))) if err.is_conflict() => {
                tracing::debug!(device_name = %device_name, "DPU device already exists (concurrent create)");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check if a DPU device is ready.
    pub async fn is_dpu_device_ready(&self, dpu_device_name: &str) -> Result<bool, DpfError> {
        let device =
            DpuDeviceRepository::get(&*self.repo, dpu_device_name, &self.namespace).await?;
        let Some(device) = device else {
            return Err(DpfError::not_found("DPUDevice", dpu_device_name));
        };

        let Some(status) = device.status else {
            return Ok(false);
        };

        let Some(conditions) = status.conditions else {
            return Ok(false);
        };

        Ok(conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True"))
    }

    /// Delete a DPU device.
    pub async fn delete_dpu_device(&self, dpu_device_name: &str) -> Result<(), DpfError> {
        DpuDeviceRepository::delete(&*self.repo, dpu_device_name, &self.namespace).await
    }
}

impl<R: DpuNodeRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Register a new DPU node (host with DPUs).
    ///
    /// This operation is idempotent - if the node already exists, it will be
    /// updated with the new configuration. This is important for multi-DPU setups
    /// where multiple concurrent state machine invocations may call this method.
    pub async fn register_dpu_node(&self, info: DpuNodeInfo) -> Result<(), DpfError> {
        let node_name = dpu_node_name(&info.node_id);

        let node = DPUNode {
            metadata: ObjectMeta {
                name: Some(node_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: {
                    let labels = self.labeler.node_labels();
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
                    info.dpu_device_names
                        .into_iter()
                        .map(|id| DpuNodeDpus { name: id })
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
            Err(DpfError::KubeError(kube::Error::Api(ref err))) if err.is_conflict() => {
                tracing::debug!(node = %node_name, "DPU node already exists (concurrent create)");
                Ok(())
            }
            Err(e) => Err(e),
        }
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
        let node_id = node_id_from_node_name(node_name);
        let dpu_name = dpu_name(dpu_device_name, node_id);
        let dpu = DpuRepository::get(&*self.repo, &dpu_name, &self.namespace).await?;

        let Some(dpu) = dpu else {
            return Err(DpfError::not_found("DPU", dpu_name));
        };

        let Some(status) = dpu.status else {
            return Err(DpfError::InvalidState(format!(
                "DPU {dpu_name} has no status"
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
        let node_id = node_id_from_node_name(node_name);
        let dpu_name = dpu_name(dpu_device_name, node_id);
        DpuRepository::delete(&*self.repo, &dpu_name, &self.namespace).await
    }
}

impl<R: DpuNodeMaintenanceRepository, L> DpfSdk<R, L> {
    /// Release the hold on a DPU node maintenance.
    pub async fn release_maintenance_hold(&self, node_name: &str) -> Result<(), DpfError> {
        let maintenance_name = format!("{}-hold", node_name);
        let patch = json!({
            "metadata": {
                "annotations": {
                    HOLD_ANNOTATION: "false"
                }
            }
        });
        DpuNodeMaintenanceRepository::patch(&*self.repo, &maintenance_name, &self.namespace, patch)
            .await
    }
}

impl<R: DpuRepository + DpuNodeRepository + DpuDeviceRepository, L: ResourceLabeler> DpfSdk<R, L> {
    /// Force delete a managed host and all its DPU resources.
    ///
    /// In the DPUDeployment (M4) model we remove the DPUNode and DPUDevices so DPF has no record
    /// of the DPU; no status patch to Error. Best-effort: remove controlled label, delete node,
    /// delete all DPU devices.
    pub async fn force_delete_host(
        &self,
        node_name: &str,
        dpu_device_names: &[String],
    ) -> Result<(), DpfError> {
        let node = DpuNodeRepository::get(&*self.repo, node_name, &self.namespace).await?;

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
            if let Err(e) = DpuDeviceRepository::delete(&*self.repo, name, &self.namespace).await {
                tracing::warn!("Failed to delete DPU device {}: {}", name, e);
            }
        }

        Ok(())
    }

    /// Force delete a single DPU and its device.
    ///
    /// In M4 we delete the DPU CR and DPUDevice; no status patch to Error.
    pub async fn force_delete_dpu(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<(), DpfError> {
        let node_id = node_id_from_node_name(node_name);
        let dpu_name = dpu_name(dpu_device_name, node_id);
        if let Err(e) = DpuRepository::delete(&*self.repo, &dpu_name, &self.namespace).await {
            tracing::warn!("Failed to delete DPU {}: {}", dpu_name, e);
        }
        if let Err(e) =
            DpuDeviceRepository::delete(&*self.repo, dpu_device_name, &self.namespace).await
        {
            tracing::warn!("Failed to delete DPU device {}: {}", dpu_device_name, e);
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
    pub fn watcher(&self) -> DpuWatcherBuilder<R> {
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
    use crate::crds::dpus_generated::DPU;
    use crate::repository::{DpuDeviceRepository, DpuNodeRepository, DpuRepository};
    use crate::types::{DpuDeviceInfo, DpuNodeInfo};

    const TEST_NAMESPACE: &str = "test-namespace";

    #[derive(Clone, Default)]
    struct SdkMock {
        devices: Arc<RwLock<BTreeMap<String, DPUDevice>>>,
        nodes: Arc<RwLock<BTreeMap<String, DPUNode>>>,
        dpus: Arc<RwLock<BTreeMap<String, DPU>>>,
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
            self.devices
                .write()
                .unwrap()
                .insert(Self::key(d), d.clone());
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
            self.nodes.write().unwrap().insert(Self::key(n), n.clone());
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

    #[tokio::test]
    async fn test_register_dpu_device() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
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
            dpu_device_names: vec!["dpu-001".to_string(), "dpu-002".to_string()],
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].metadata.name,
            Some("dpu-node-host-001".to_string())
        );
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
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
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
            dpu_device_names: vec!["dpu-001".to_string()],
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);

        sdk.delete_dpu_node("dpu-node-host-001").await.unwrap();

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
            ])
        }

        fn node_labels(&self) -> BTreeMap<String, String> {
            BTreeMap::from([("test/node".to_string(), "true".to_string())])
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
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
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
    }

    #[tokio::test]
    async fn test_dpu_device_no_labels_without_labeler() {
        let mock = SdkMock::new();
        let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NAMESPACE, String::new())
            .build_without_resources()
            .await
            .unwrap();

        let info = DpuDeviceInfo {
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123456".to_string(),
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
            dpu_device_names: vec!["dpu-001".to_string()],
        };

        sdk.register_dpu_node(info).await.unwrap();

        let nodes = DpuNodeRepository::list(&mock, TEST_NAMESPACE)
            .await
            .unwrap();
        let node = &nodes[0];
        let labels = node.metadata.labels.as_ref().unwrap();

        assert_eq!(labels.get("test/node"), Some(&"true".to_string()));
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
            dpu_device_names: vec!["dpu-001".to_string()],
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
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN123".to_string(),
        };
        sdk.register_dpu_device(device_info).await.unwrap();

        let dpu_name = "dpu-node-dpu-001-dpu-001";
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
                dpu_flavor: Some("carbide-dpu-flavor".to_string()),
                dpu_node_name: "dpu-node-dpu-001".to_string(),
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

        sdk.reprovision_dpu("dpu-001", "dpu-node-dpu-001")
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
            device_name: "dpu-001".to_string(),
            dpu_bmc_ip: "10.0.0.10".to_string(),
            host_bmc_ip: "10.0.0.1".to_string(),
            serial_number: "SN111".to_string(),
        };

        let info2 = DpuDeviceInfo {
            device_name: "dpu-002".to_string(),
            dpu_bmc_ip: "10.0.0.20".to_string(),
            host_bmc_ip: "10.0.0.2".to_string(),
            serial_number: "SN222".to_string(),
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
        assert!(!config.bfb_url.is_empty());
        assert_eq!(config.deployment_name, "carbide-deployment");
        assert!(config.services.is_empty());
    }

    #[tokio::test]
    async fn test_init_config_custom() {
        let config = InitDpfResourcesConfig {
            bfb_url: "http://example.com/test.bfb".to_string(),
            deployment_name: "my-deployment".to_string(),
            services: vec![],
            bfcfg_template: None,
        };

        assert_eq!(config.bfb_url, "http://example.com/test.bfb");
        assert_eq!(config.deployment_name, "my-deployment");
    }
}
