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

//! The Carbide DPF library.
//!
//! This library provides the Carbide DPF implementation.

pub mod crds;
#[cfg(test)]
pub mod test;
pub mod utils;

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{ListParams, Patch, PatchParams, PostParams};
use kube::core::ObjectMeta;
use kube::{Api, Client};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use tera::{Context, Tera};
use tokio::time::Duration;

use crate::crds::bfb_generated::{BFB, BfbSpec, BfbStatusPhase};
use crate::crds::dpu_flavor_generated::{DPUFlavor, DpuFlavorDpuMode, DpuFlavorSpec};
use crate::crds::dpu_set_generated::{
    DPUSet, DpuSetDpuNodeSelector, DpuSetDpuTemplate, DpuSetDpuTemplateSpec,
    DpuSetDpuTemplateSpecBfb, DpuSetDpuTemplateSpecNodeEffect, DpuSetSpec, DpuSetStrategy,
    DpuSetStrategyType,
};

pub const DPF_NAMESPACE: &str = "dpf-operator-system";
pub const FORGE_NAMESPACE: &str = "forge-system";
const BFB_NAME: &str = "bf-bundle";
const DPUSET_NAME: &str = "carbide-dpu-set";
const DPUFLAVOR_NAME: &str = "carbide-dpu-flavor";
const SECRET_NAME: &str = "bmc-shared-password";

const BFCFG_CONFIGMAP_NAME: &str = "carbide-dpf-bf-cfg-template";
const BF_CFG_DATA_TEMPLATE: &str = include_str!("../files/bf.cfg");
const BF_CFG_FW_UPDATE_DATA_TEMPLATE: &str = include_str!("../../../pxe/templates/bmc_fw_update");

const BFB_URL: &str = "http://{pxe-ip}/public/blobs/internal/aarch64/forge.bfb";

static DPF_INIT: OnceLock<Result<(), eyre::Report>> = OnceLock::new();

/// Creates a BFB object with the given input.
fn bfb_crd(name: &str, pxe_ip: &str) -> BFB {
    BFB {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(DPF_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: BfbSpec {
            file_name: None,
            url: BFB_URL.replace("{pxe-ip}", pxe_ip),
        },
        status: None,
    }
}

/// Initializes the DPF library by setting up the cryptographic provider.
///
/// This function ensures that the rustls crypto provider is installed globally
/// before any DPF operations are performed. It uses a `OnceLock` to guarantee
/// that initialization happens exactly once, even if called multiple times or
/// from multiple threads.
///
/// # Returns
/// * `&'static Result<(), eyre::Report>` - A static reference to the initialization result.
///   Returns `Ok(())` if the crypto provider was successfully installed or was already present.
///   Returns `Err` if the crypto provider installation failed.
///
/// # Thread Safety
/// This function is thread-safe and idempotent. Multiple concurrent calls will only
/// perform the initialization once.
pub fn init() -> Result<(), eyre::Report> {
    let res = DPF_INIT.get_or_init(|| {
        // Set crypto provider regardless of DPF flag.
        if CryptoProvider::get_default().is_none() {
            CryptoProvider::install_default(aws_lc_rs::default_provider())
                .map_err(|e| eyre::eyre!(format!("Install default error: {e:?}")))?
        }

        Ok(())
    });

    match res {
        Ok(()) => Ok(()),
        // eyre::report does not implement Clone or Copy.
        Err(err) => Err(eyre::eyre!(err)),
    }
}

/// Trait for a Kubernetes client implementation.
#[async_trait::async_trait]
pub trait KubeImpl: Send + Sync + std::fmt::Debug + 'static {
    async fn get_kube_client(&self) -> Result<kube::Client, DpfError>;

    // This is Test implementation to avoid deleting kube CRs.
    async fn force_delete_machine(
        &self,
        ip: &str,
        dpu_machine_ids: &[String],
    ) -> Result<(), DpfError> {
        tracing::info!(
            "Force deleting machine {ip} with DPU machine ids {dpu_machine_ids:?} in TEST env."
        );
        Ok(())
    }
}

/// Production Kubernetes client implementation.
#[derive(Debug, Clone)]
pub struct Production;

#[async_trait::async_trait]
impl KubeImpl for Production {
    async fn get_kube_client(&self) -> Result<kube::Client, DpfError> {
        let client = Client::try_default().await.map_err(DpfError::KubeError)?;
        Ok(client)
    }

    // Production implementation does the real deletion.
    async fn force_delete_machine(
        &self,
        ip: &str,
        dpu_machine_ids: &[String],
    ) -> Result<(), DpfError> {
        utils::force_delete_managed_host(self, ip, dpu_machine_ids).await
    }
}

/// Error type for DPF operations.
#[derive(thiserror::Error, Debug)]
pub enum DpfError {
    #[error("Kubernetes client error: {0}")]
    KubeError(#[from] kube::Error),
    #[error("BFB is still not ready after {0} seconds.")]
    BFBNotReady(u32),
    #[error("Template error: {0}")]
    TemplateError(#[from] tera::Error),
    #[error("Object {0} not found: {1}")]
    NotFound(&'static str, String),
    #[error("Annotation not found: {0} in object {1}")]
    AnnotationNotFound(String, String),
    #[error("Object {0} already exists: {1}")]
    AlreadyExists(&'static str, String),
}

/// Creates all necessary Custom Resource Definitions (CRDs) and a Secret in the Kubernetes cluster to set up the DPF (Data Processing Framework) system.
///
/// This function coordinates the following steps:
/// 1. Ensures a Kubernetes Secret exists to store the BMC (Baseboard Management Controller) password, creating it if necessary.
/// 2. Ensures the DPUFlavor CRD exists in the cluster, creating it if necessary.
/// 3. Creates a new BFB (BlueField Bundle) CRD and waits for it to become ready.
/// 4. Creates or updates the DPUSet CRD, pointing it to the new BFB.
/// 5. Deletes all outdated BFB CRDs, retaining only the most recently created one.
/// 6. Creates or updates the ConfigMap containing the bf.cfg configuration using the provided context.
///
/// # Arguments
/// * `bfcfg_context` - A context map used for rendering the bf.cfg template and populating the ConfigMap.
/// * `bmc_password` - The BMC root password to store in the Secret.
///
/// # Returns
/// * `Result<(), DpfError>` - Returns Ok if all resources are created or exist; returns a DpfError if any step fails.
pub async fn create_crds_and_secret(
    bfcfg_context: HashMap<String, String>,
    bmc_password: String,
) -> Result<(), DpfError> {
    let mode = Production {};
    create_crds_and_secret_with_client(bfcfg_context, bmc_password, &mode).await
}

/// Creates all required CRDs and a Secret using the provided Kubernetes client implementation.
///
/// This function allows injection of a custom `KubeImpl` (real or mockable) for testing or production use.
/// It performs the following steps:
/// 1. Ensures the Kubernetes Secret for the BMC password exists.
/// 2. Ensures the DPUFlavor CRD exists in the cluster.
/// 3. Creates a new BFB CRD and waits for it to become ready.
/// 4. Creates or updates the DPUSet CRD, referencing the new BFB.
/// 5. Deletes all outdated BFB CRDs, keeping only the latest.
/// 6. Creates/updates the ConfigMap for bf.cfg configuration.
///
/// # Arguments
/// * `bfcfg_context` - Context for rendering the bf.cfg template into the ConfigMap.
/// * `bmc_password` - The BMC root password to be stored in the Secret.
/// * `mode` - The injected KubeImpl client (used for actual or test clients).
///
/// # Returns
/// * `Result<(), DpfError>` - Ok if setup is successful, or an error if any step fails.
pub async fn create_crds_and_secret_with_client(
    bfcfg_context: HashMap<String, String>,
    bmc_password: String,
    mode: &impl KubeImpl,
) -> Result<(), DpfError> {
    // Step 0: Create secret for bmc password
    create_secret_for_bmc_password(bmc_password, mode).await?;

    // Step 1: Create DPUFlavor if not exists
    create_dpuflavor_if_not_exists(mode).await?;

    // Step 3: Create and wait for BFB
    let bfb_name = create_and_wait_for_bfb(mode).await?;

    // Step 4: Create DPUSet and update bfb name in it.
    create_dpuset_crd(&bfb_name, mode).await?;

    // Step 5: Delete all old BFB CRDs
    delete_all_old_bfb_crds(bfb_name, mode).await?;

    // Step 6: Create configmap for bf.cfg
    // No need tor edeploy dpf-operator-config as it will pick the configmap changes automatically.
    create_bfcfg_configmap(bfcfg_context, mode).await?;

    Ok(())
}

/// Creates a Kubernetes Secret containing the provided BMC password if it does not already exist.
///
/// # Arguments
/// * `password` - The BMC root password to store in the Secret.
///
/// # Returns
/// * `Result<(), DpfError>` - Returns Ok(()) if the secret is ensured or created successfully, or a DpfError on failure.
///
/// This function is idempotent: if the secret already exists, it will not recreate or overwrite it.
async fn create_secret_for_bmc_password(
    password: String,
    kube_impl: &impl KubeImpl,
) -> Result<(), DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let secrets = Api::<Secret>::namespaced(client, DPF_NAMESPACE);

    if let Some(existing_secret) = secrets.get_opt(SECRET_NAME).await? {
        tracing::info!(
            "Secret '{}' already exists. Skipping creation.",
            existing_secret.metadata.name.unwrap()
        );
    } else {
        // Secret does not exist, define it
        let mut data = BTreeMap::new();
        data.insert("password".into(), k8s_openapi::ByteString(password.into()));

        let new_secret = Secret {
            metadata: ObjectMeta {
                name: Some(SECRET_NAME.to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        secrets.create(&PostParams::default(), &new_secret).await?;
        tracing::info!("Secret '{}' created successfully.", SECRET_NAME);
    }

    Ok(())
}

/// Creates or updates a Kubernetes ConfigMap for `bf.cfg` using the values in `bfcfg_context`.
///
/// # Arguments
/// * `bfcfg_context` - A HashMap containing key-value pairs used to render the `bf.cfg` template.
///
/// # Returns
/// * `Result<(), DpfError>` - Returns Ok(()) if successful, or a `DpfError` if an error occurred.
pub async fn create_bfcfg_configmap(
    bfcfg_map: HashMap<String, String>,
    kube_impl: &impl KubeImpl,
) -> Result<(), DpfError> {
    // Render the bf.cfg file from the provided context using the Tera template engine.
    let context = Context::from_serialize(&bfcfg_map).map_err(DpfError::TemplateError)?;
    let bf_cfg =
        Tera::one_off(BF_CFG_DATA_TEMPLATE, &context, false).map_err(DpfError::TemplateError)?;
    let data = Some(BTreeMap::from([("BF_CFG_TEMPLATE".to_string(), bf_cfg)]));

    // Initialize Kubernetes client and construct the API object for ConfigMaps.
    let client = kube_impl.get_kube_client().await?;
    let configmaps = Api::<ConfigMap>::namespaced(client, DPF_NAMESPACE);

    // Build the ConfigMap object.
    let configmap_cr = ConfigMap {
        immutable: Some(false),
        metadata: ObjectMeta {
            name: Some(BFCFG_CONFIGMAP_NAME.to_string()),
            namespace: Some(DPF_NAMESPACE.to_string()),
            ..Default::default()
        },
        data,
        binary_data: None,
    };

    // Apply the ConfigMap using server-side apply.
    configmaps
        .patch(
            BFCFG_CONFIGMAP_NAME,
            &PatchParams::apply("carbide-controller").force(),
            &Patch::Apply(&configmap_cr),
        )
        .await
        .map_err(DpfError::KubeError)?;
    Ok(())
}

pub fn get_fw_update_data() -> String {
    let context: Context = Context::new();
    let rendered: String =
        Tera::one_off(BF_CFG_FW_UPDATE_DATA_TEMPLATE, &(context), false).unwrap_or_default();
    rendered
}

/// This function ensures that a DPUFlavor Custom Resource (CR) exists in the Kubernetes cluster.
///
/// - Tries to connect to the cluster and initialize the API for DPUFlavor resources.
/// - Checks if a DPUFlavor with the name `DPUFLAVOR_NAME` already exists in the current namespace using `get_opt`.
/// - If the DPUFlavor does not exist:
///     - Constructs a new DPUFlavor CR object with a "ZeroTrust" mode and no additional configuration.
///     - Creates the resource in the cluster with default post parameters.
/// - Returns `Ok(())` if successful, or a wrapped error if the Kubernetes client or API calls fail.
async fn create_dpuflavor_if_not_exists(kube_impl: &impl KubeImpl) -> Result<(), DpfError> {
    // Initialize Kubernetes client and the API object for DPUFlavor in the given namespace.
    let client = kube_impl.get_kube_client().await?;
    let dpuflavors = Api::<DPUFlavor>::namespaced(client, DPF_NAMESPACE);

    // Attempt to retrieve the DPUFlavor CR; proceed if it does not exist.
    if dpuflavors
        .get_opt(DPUFLAVOR_NAME)
        .await
        .map_err(DpfError::KubeError)?
        .is_none()
    {
        // Construct the DPUFlavor CR with default/empty fields and "ZeroTrust" mode.
        let dpuflavor_cr = DPUFlavor {
            metadata: ObjectMeta {
                name: Some(DPUFLAVOR_NAME.to_string()),
                namespace: Some(DPF_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: DpuFlavorSpec {
                dpu_mode: Some(DpuFlavorDpuMode::ZeroTrust),
                dpu_resources: None,
                bfcfg_parameters: None,
                config_files: None,
                containerd_config: None,
                grub: None,
                host_network_interface_configs: None,
                nvconfig: None,
                ovs: None,
                sysctl: None,
                system_reserved_resources: None,
            },
        };
        // Create the DPUFlavor CR in the cluster.
        dpuflavors
            .create(&PostParams::default(), &dpuflavor_cr)
            .await
            .map_err(DpfError::KubeError)?;
    }
    Ok(())
}

/// This function ensures that a DPUSet Custom Resource (CR) exists in the Kubernetes cluster.
///
/// - Tries to connect to the cluster and initialize the API for DPUSet resources.
/// - Checks if a DPUSet with the name `DPUSET_NAME` already exists in the current namespace using `get_opt`.
/// - If the DPUSet does not exist:
///     - Constructs a new DPUSet CR object with default/empty fields.
///     - Creates the resource in the cluster with default post parameters.
/// - Returns `Ok(())` if successful, or a wrapped error if the Kubernetes client or API calls fail.
async fn create_dpuset_crd(bfb_name: &str, kube_impl: &impl KubeImpl) -> Result<(), DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let dpusets = Api::<DPUSet>::namespaced(client, DPF_NAMESPACE);

    // Construct the DPUSet CR with default/empty fields.
    let dpuset_cr = DPUSet {
        metadata: ObjectMeta {
            name: Some(DPUSET_NAME.to_string()),
            namespace: Some(DPF_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: DpuSetSpec {
            dpu_node_selector: Some(DpuSetDpuNodeSelector {
                match_expressions: None,
                match_labels: Some(BTreeMap::from([(
                    "carbide.nvidia.com/controlled.node".to_string(),
                    "true".to_string(),
                )])),
            }),
            dpu_selector: None,
            dpu_template: DpuSetDpuTemplate {
                annotations: None,
                spec: Some(DpuSetDpuTemplateSpec {
                    bfb: Some(DpuSetDpuTemplateSpecBfb {
                        name: Some(bfb_name.to_string()),
                    }),
                    cluster: None,
                    dpu_flavor: DPUFLAVOR_NAME.to_string(),
                    node_effect: Some(DpuSetDpuTemplateSpecNodeEffect {
                        apply_on_label_change: Some(false),
                        custom_action: None,
                        custom_label: None,
                        drain: None,
                        force: Some(false),
                        hold: Some(true),
                        no_effect: None,
                        node_maintenance_additional_requestors: None,
                        taint: None,
                    }),
                }),
            },
            strategy: Some(DpuSetStrategy {
                rolling_update: None,
                r#type: Some(DpuSetStrategyType::OnDelete),
            }),
        },
        status: None,
    };

    // Apply the DPUSet CR.
    dpusets
        .patch(
            DPUSET_NAME,
            &PatchParams::apply("carbide-controller").force(),
            &Patch::Apply(&dpuset_cr),
        )
        .await
        .map_err(DpfError::KubeError)?;
    tracing::info!("DPUSet CR applied successfully.");
    Ok(())
}

/// This function checks if a BFB Custom Resource (CR) exists in the Kubernetes cluster.
///
/// - Tries to connect to the cluster and initialize the API for BFB resources.
/// - Checks if a BFB with the name `BFB_NAME` already exists in the current namespace using `get_opt`.
/// - Returns `Ok(Option<BFB>)` containing the BFB CR if it exists, or `Ok(None)` if it does not exist.
/// - Returns a wrapped error if the Kubernetes client or API calls fail.
pub async fn check_if_bfb_exists(
    name: &str,
    kube_impl: &impl KubeImpl,
) -> Result<Option<BFB>, DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let bfb = Api::<BFB>::namespaced(client, DPF_NAMESPACE);
    let bfb_crd = bfb.get_opt(name).await.map_err(DpfError::KubeError)?;
    Ok(bfb_crd)
}

/// This function deletes a BFB Custom Resource (CR) from the Kubernetes cluster.
///
/// - Tries to connect to the cluster and initialize the API for BFB resources.
/// - Deletes the BFB CR with the name `BFB_NAME` using default delete parameters.
/// - Returns `Ok(true)` if successful, or a wrapped error if the Kubernetes client or API calls fail.
pub async fn delete_bfb_crd(name: &str, kube_impl: &impl KubeImpl) -> Result<(), DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let bfb = Api::<BFB>::namespaced(client, DPF_NAMESPACE);
    bfb.delete(name, &Default::default())
        .await
        .map_err(DpfError::KubeError)?;
    Ok(())
}

/// Deletes all BFB (BlueField Bundle) Custom Resources in the Kubernetes cluster
/// except for the one with the provided `latest_bfb_name`.
///
/// # Arguments
/// * `latest_bfb_name` - The name of the BFB CRD to keep (all others will be deleted).
///
/// # Returns
/// * `Result<(), DpfError>` - Returns Ok(()) if successful, or a DpfError on failure.
async fn delete_all_old_bfb_crds(
    latest_bfb_name: String,
    kube_impl: &impl KubeImpl,
) -> Result<(), DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let bfb = Api::<BFB>::namespaced(client, DPF_NAMESPACE);
    let bfb_crds = bfb.list(&ListParams::default()).await?;
    for bfb_crd in bfb_crds {
        let name = bfb_crd.metadata.name.unwrap_or_default();
        if name != latest_bfb_name {
            tracing::info!("Deleting BFB CRD {name}");
            if let Err(err) = bfb.delete(&name, &Default::default()).await {
                tracing::error!("Failed to delete BFB CRD {name}: {err}");
            }
        }
    }
    Ok(())
}

/// Creates a BFB (BlueField Bundle) Custom Resource in the Kubernetes cluster and waits until it is ready.
///
/// This function performs the following:
/// - Generates a unique BFB CRD name using the base name and a UUID.
/// - Attempts up to 3 times to:
///   * Delete any existing BFB CRD with the generated name to ensure a clean state.
///   * Create a new BFB CRD in the Kubernetes cluster.
///   * Waits (polling every second, up to 60 seconds) for the BFB CRD's `.status.phase` to become "Ready".
///     - If the status becomes "Error", it waits 15 seconds and tries again.
/// - Returns the name of the created BFB CRD upon success.
///
/// # Returns
/// * `Ok(String)` - The name of the ready BFB CRD.
/// * `Err(DpfError)` - If creation fails, the CRD is not ready in time, or a Kubernetes error occurs.
///
/// # Errors
/// Returns `DpfError::BFBNotReady` if the BFB CRD does not become ready after all attempts,
/// or propagates errors from Kubernetes or API operations.
pub async fn create_and_wait_for_bfb(kube_impl: &impl KubeImpl) -> Result<String, DpfError> {
    // All the constants might need calibration once we move to vanilla BFB.
    const TIMEOUT_SECONDS: u32 = 60;
    tracing::info!("Starting creation and waiting for BFB to become ready");

    let client = kube_impl.get_kube_client().await?;
    let bfb = Api::<BFB>::namespaced(client, DPF_NAMESPACE);
    let pxe_ip = pxe_ip(kube_impl).await?;

    for attempt in 0..3 {
        let bfb_name = format!("{}-{}", BFB_NAME, uuid::Uuid::new_v4());
        tracing::info!("Creating new BFB CRD {}...", bfb_name);
        bfb.create(&PostParams::default(), &bfb_crd(&bfb_name, &pxe_ip))
            .await
            .map_err(DpfError::KubeError)?;

        for wait_sec in 0..TIMEOUT_SECONDS {
            if let Some(bfb_crd) = check_if_bfb_exists(&bfb_name, kube_impl).await?
                && let Some(status) = bfb_crd.status
            {
                tracing::debug!(
                    "Checked BFB CRD status at second {}: {:?}",
                    wait_sec,
                    status.phase
                );

                if matches!(status.phase, BfbStatusPhase::Ready) {
                    tracing::info!(
                        "BFB CRD is ready after {} seconds (attempt {})",
                        wait_sec,
                        attempt + 1
                    );
                    return Ok(bfb_name);
                }
                if matches!(status.phase, BfbStatusPhase::Error) {
                    // This is possible if pxe is not up yet.
                    tracing::warn!(
                        "BFB CRD status is Error. Waiting 10 seconds before retry in attempt {}",
                        attempt + 1
                    );
                    // It will deleted in the delete_all_old_bfb_crds function.
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    continue;
                }
            } else {
                tracing::debug!(
                    "BFB CRD not present or status missing at second {}",
                    wait_sec
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        tracing::warn!(
            "BFB CRD did not become ready in {} seconds for attempt {}. Retrying if attempts remain.",
            TIMEOUT_SECONDS,
            attempt + 1
        );
    }
    tracing::error!(
        "BFB CRD was not ready after {} attempts of {} seconds each. Giving up.",
        3,
        TIMEOUT_SECONDS
    );
    Err(DpfError::BFBNotReady(TIMEOUT_SECONDS))
}

/// Retrieves the load balancer IP address for the carbide-pxe-external service.
///
/// # Arguments
/// * `kube_impl` - Kubernetes implementation for cluster interaction
///
/// # Returns
/// * `Ok(String)` - The load balancer IP address
/// * `Err(DpfError)` - If the service or IP is not found, or on Kubernetes API errors
async fn pxe_ip(kube_impl: &impl KubeImpl) -> Result<String, DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let services = Api::<k8s_openapi::api::core::v1::Service>::namespaced(client, FORGE_NAMESPACE);

    let pxe_service = services.get("carbide-pxe-external").await?;

    let load_balancer_ip = pxe_service
        .status
        .and_then(|status| status.load_balancer)
        .and_then(|lb| lb.ingress)
        .and_then(|x| x.first().cloned())
        .and_then(|x| x.ip)
        .ok_or_else(|| DpfError::NotFound("loadbalancer IP", "carbide-pxe-external".to_string()))?;

    Ok(load_balancer_ip)
}
