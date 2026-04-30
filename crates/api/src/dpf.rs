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

//! DPF SDK trait abstraction for testability.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use carbide_dpf::{
    BmcPasswordProvider, DpfError, DpfSdk, DpuDeviceInfo, DpuNodeInfo, DpuPhase, DpuWatcher,
    KubeRepository, ResourceLabeler, node_id_from_dpu_node_cr_name,
};
use sqlx::PgPool;
use tokio::task::JoinSet;

use crate::cfg::file::CarbideConfig;
use crate::state_controller::controller::Enqueuer;
use crate::state_controller::machine::io::MachineStateControllerIO;

const BF_CFG_TEMPLATE: &str = include_str!("../files/bf.cfg");
const BF_CFG_FW_UPDATE_TEMPLATE: &str = include_str!("../../../pxe/templates/bmc_fw_update");

const API_URL_KEY: &str = "api_url";
const PXE_URL_KEY: &str = "pxe_url";
const API_URL: &str = "https://carbide-api.forge";
const PXE_URL: &str = "http://carbide-pxe.forge";
const BMC_FW_UPDATE_KEY: &str = "bmc_fw_update";
const SECONDS_SINCE_EPOCH_KEY: &str = "seconds_since_epoch";
const HBN_REPS_KEY: &str = "forge_hbn_reps";
const HBN_SFS_KEY: &str = "forge_hbn_sfs";
const VF_INTERCEPT_BRIDGE_NAME_KEY: &str = "forge_vf_intercept_bridge_name";
const HOST_INTERCEPT_BRIDGE_NAME_KEY: &str = "forge_host_intercept_bridge_name";
const HOST_INTERCEPT_HBN_PORT_KEY: &str = "forge_host_intercept_hbn_port";
const HOST_INTERCEPT_BRIDGE_PORT_KEY: &str = "forge_host_intercept_bridge_port";
const VF_INTERCEPT_HBN_PORT_KEY: &str = "forge_vf_intercept_hbn_port";
const VF_INTERCEPT_BRIDGE_PORT_KEY: &str = "forge_vf_intercept_bridge_port";
const VF_INTERCEPT_BRIDGE_SF_REPRESENTOR_KEY: &str = "forge_vf_intercept_bridge_sf_representor";
const VF_INTERCEPT_BRIDGE_SF_HBN_BRIDGE_REPRESENTOR_KEY: &str =
    "forge_vf_intercept_bridge_sf_hbn_bridge_representor";
const VF_INTERCEPT_BRIDGE_SF_KEY: &str = "forge_vf_intercept_bridge_sf";

const BFB_PATH: &str = "/public/blobs/internal/aarch64/forge.bfb";

/// Resolve the BFB download URL by looking up the external LoadBalancer IP of
/// the `carbide-pxe-external` Service. The DPU fetches the BFB over the
/// out-of-band management network, so it needs the external IP — not an
/// in-cluster DNS name.
pub async fn resolve_bfb_url() -> Result<String, DpfError> {
    let client = kube::Client::try_default().await?;
    let services =
        kube::Api::<k8s_openapi::api::core::v1::Service>::namespaced(client, "forge-system");
    let pxe_service = services.get("carbide-pxe-external").await?;
    let pxe_ip = pxe_service
        .status
        .and_then(|s| s.load_balancer)
        .and_then(|lb| lb.ingress)
        .and_then(|ingress| ingress.first().cloned())
        .and_then(|entry| entry.ip)
        .ok_or_else(|| {
            DpfError::ConfigError("carbide-pxe-external service has no LoadBalancer IP".to_string())
        })?;
    Ok(format!("http://{pxe_ip}{BFB_PATH}"))
}

/// Trait for DPF SDK operations used by Carbide.
///
/// The DPF operator owns provisioning; Carbide declares setup (deployment, devices, node),
/// reacts to watcher callbacks, and performs reprovision/force-delete.
///
/// Reboot handling is managed via the watcher's `on_reboot_required` callback.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DpfOperations: Send + Sync + std::fmt::Debug {
    /// Register a DPU device.
    async fn register_dpu_device(&self, info: DpuDeviceInfo) -> Result<(), DpfError>;

    /// Register a DPU node.
    async fn register_dpu_node(&self, info: DpuNodeInfo) -> Result<(), DpfError>;

    /// Release the maintenance hold on a DPU node.
    async fn release_maintenance_hold(&self, node_name: &str) -> Result<(), DpfError>;

    /// Reprovision a DPU (delete DPU CR; operator creates a new one that waits on node effect).
    async fn reprovision_dpu(&self, dpu_device_name: &str, node_name: &str)
    -> Result<(), DpfError>;

    /// Force delete a host and all its DPU resources.
    async fn force_delete_host(
        &self,
        node_id: &str,
        dpu_device_names: &[String],
    ) -> Result<(), DpfError>;

    /// Get the current phase of a DPU (for status reporting).
    async fn get_dpu_phase(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<DpuPhase, DpfError>;

    /// Check if a DPU node is waiting for external reboot.
    async fn is_reboot_required(&self, node_name: &str) -> Result<bool, DpfError>;

    /// Mark DPU node as rebooted (clear the external reboot required annotation).
    async fn reboot_complete(&self, node_name: &str) -> Result<(), DpfError>;

    /// Check that a DPUNode's labels match the current expected labels.
    /// Returns `false` when the node exists but has stale labels.
    async fn verify_node_labels(&self, node_name: &str) -> Result<bool, DpfError>;
}

/// Applies carbide-specific labels to DPF resources.
///
/// Label inheritance in DPF:
/// - DPUDevice labels propagate to the DPU CR created by the operator.
/// - DPUNode static labels (`node_labels`) are used by DPUDeployment's
///   `dpuNodeSelector` to match nodes, and also propagate to DPU CRs.
/// - DPUNode contextual labels (`node_context_labels`) are only set at
///   creation and propagate to DPU CRs, but are not part of selectors.
pub struct CarbideDPFLabeler {
    node_label_key: String,
}

impl CarbideDPFLabeler {
    pub fn new(node_label_key: String) -> Self {
        Self { node_label_key }
    }
}

impl ResourceLabeler for CarbideDPFLabeler {
    fn device_labels(&self, info: &DpuDeviceInfo) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "carbide.nvidia.com/controlled.device".to_string(),
                "true".to_string(),
            ),
            (
                "carbide.nvidia.com/host-bmc-ip".to_string(),
                info.host_bmc_ip.clone(),
            ),
            (
                "carbide.nvidia.com/host-machine-id".to_string(),
                info.host_machine_id.clone(),
            ),
            (
                "carbide.nvidia.com/dpu-machine-id".to_string(),
                info.dpu_machine_id.clone(),
            ),
        ])
    }

    fn node_labels(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (self.node_label_key.clone(), "true".to_string()),
            (
                "feature.node.kubernetes.io/dpu-enabled".to_string(),
                "true".to_string(),
            ),
        ])
    }

    fn node_context_labels(&self, info: &DpuNodeInfo) -> BTreeMap<String, String> {
        BTreeMap::from([(
            "carbide.nvidia.com/host-bmc-ip".to_string(),
            info.host_bmc_ip.clone(),
        )])
    }

    fn dpu_label_selector(&self) -> Option<String> {
        Some("carbide.nvidia.com/controlled.device=true".to_string())
    }
}

/// BMC password provider backed by the Carbide credential manager.
pub struct CarbideBmcPasswordProvider(Arc<dyn forge_secrets::credentials::CredentialReader>);

impl CarbideBmcPasswordProvider {
    pub fn new(credential_reader: Arc<dyn forge_secrets::credentials::CredentialReader>) -> Self {
        Self(credential_reader)
    }
}

#[async_trait]
impl BmcPasswordProvider for CarbideBmcPasswordProvider {
    async fn get_bmc_password(&self) -> Result<String, DpfError> {
        use forge_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
        let key = CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::SiteWideRoot,
        };
        match self.0.get_credentials(&key).await {
            Ok(Some(Credentials::UsernamePassword { password, .. })) => Ok(password),
            Ok(_) => Err(DpfError::InvalidState(
                "Site wide BMC root credentials not set".into(),
            )),
            Err(e) => Err(DpfError::InvalidState(format!(
                "Failed to read BMC credentials: {e}"
            ))),
        }
    }
}

/// DPF SDK operations implementation that wraps the real DPF SDK.
pub struct DpfSdkOps {
    sdk: Arc<DpfSdk<KubeRepository, CarbideDPFLabeler>>,
    _watcher: DpuWatcher,
}

impl DpfSdkOps {
    /// Create a new DpfSdkOps using the DPF SDK and sets up watcher callbacks to trigger carbide state handling.
    pub fn new(
        sdk: Arc<DpfSdk<KubeRepository, CarbideDPFLabeler>>,
        db_pool: PgPool,
        join_set: &mut JoinSet<()>,
    ) -> std::io::Result<Self> {
        let watcher = sdk
            .watcher()
            .on_dpu_event(|event| async move {
                tracing::debug!(
                    dpu = %event.dpu_name,
                    device_name = %event.device_name,
                    node = %event.node_name,
                    phase = ?event.phase,
                    "DPF DPU event"
                );
                Ok(())
            })
            .on_reboot_required({
                let db_pool = db_pool.clone();
                move |event| {
                    let db_pool = db_pool.clone();
                    async move {
                        tracing::info!(
                            node = %event.node_name,
                            host = %event.host_bmc_ip,
                            "DPF reboot required"
                        );
                        enqueue_host(&db_pool, &event.node_name, "reboot").await
                    }
                }
            })
            .on_dpu_ready({
                let db_pool = db_pool.clone();
                move |event| {
                    let db_pool = db_pool.clone();
                    async move {
                        tracing::info!(
                            dpu = %event.dpu_name,
                            device_name = %event.device_name,
                            node = %event.node_name,
                            "DPF DPU ready"
                        );
                        enqueue_host(&db_pool, &event.node_name, "ready").await
                    }
                }
            })
            .on_maintenance_needed({
                let db_pool = db_pool.clone();
                move |event| {
                    let db_pool = db_pool.clone();
                    async move {
                        tracing::info!(
                            node = %event.node_name,
                            "DPF maintenance needed (NodeEffect phase)"
                        );
                        enqueue_host(&db_pool, &event.node_name, "maintenance").await
                    }
                }
            })
            .on_error({
                move |event| {
                    let db_pool = db_pool.clone();
                    async move {
                        tracing::error!(
                            dpu = %event.dpu_name,
                            device_name = %event.device_name,
                            node = %event.node_name,
                            "DPF DPU entered error phase"
                        );
                        enqueue_host(&db_pool, &event.node_name, "error").await
                    }
                }
            })
            .with_join_set(join_set)
            .start()?;

        Ok(Self {
            sdk,
            _watcher: watcher,
        })
    }
}

/// Look up a host by DPUNode CR name and enqueue it for state handling.
/// CR name format: `node-{dpf_id}`, where `dpf_id` is the host's BMC MAC
/// address with colons replaced by hyphens.
async fn enqueue_host(db_pool: &PgPool, node_name: &str, reason: &str) -> Result<(), DpfError> {
    let bmc_mac_id = node_id_from_dpu_node_cr_name(node_name);
    let bmc_mac: mac_address::MacAddress = bmc_mac_id
        .replace('-', ":")
        .parse()
        .map_err(|e| DpfError::InvalidState(format!("Invalid BMC MAC in node name: {e}")))?;

    let host_machine_id = {
        let mut conn = db_pool.acquire().await.map_err(|e| {
            DpfError::InvalidState(format!("Failed to acquire database connection: {e}"))
        })?;
        db::machine_topology::find_machine_id_by_bmc_mac(&mut conn, bmc_mac)
            .await
            .map_err(|e| {
                DpfError::InvalidState(format!("DB error looking up host by BMC MAC: {e}"))
            })?
    };

    let Some(host_machine_id) = host_machine_id else {
        tracing::warn!(node = %node_name, %bmc_mac, reason, "Could not find host for DPF node");
        return Ok(());
    };

    let host = {
        let mut conn = db_pool.acquire().await.map_err(|e| {
            DpfError::InvalidState(format!("Failed to acquire database connection: {e}"))
        })?;
        db::machine::find_one(
            &mut *conn,
            &host_machine_id,
            model::machine::machine_search_config::MachineSearchConfig::default(),
        )
        .await
        .map_err(|e| DpfError::InvalidState(format!("DB error looking up host: {e}")))?
    };

    let Some(host) = host else {
        tracing::warn!(node = %node_name, reason, "Could not find host for DPF node");
        return Ok(());
    };

    Enqueuer::<MachineStateControllerIO>::new(db_pool.clone())
        .enqueue_object(&host.id)
        .await
        .map_err(|e| {
            DpfError::InvalidState(format!("Failed to enqueue machine {}: {e}", host.id))
        })?;

    tracing::info!(node = %node_name, host = %host.id, reason, "Enqueued host for DPF state handling");
    Ok(())
}

impl std::fmt::Debug for DpfSdkOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpfSdkOps").finish()
    }
}

/// Delegates everything to the underlying DPF SDK.
#[async_trait]
impl DpfOperations for DpfSdkOps {
    async fn register_dpu_device(&self, info: DpuDeviceInfo) -> Result<(), DpfError> {
        self.sdk.register_dpu_device(info).await
    }

    async fn register_dpu_node(&self, info: DpuNodeInfo) -> Result<(), DpfError> {
        self.sdk.register_dpu_node(info).await
    }

    async fn release_maintenance_hold(&self, node_name: &str) -> Result<(), DpfError> {
        self.sdk.release_maintenance_hold(node_name).await
    }

    async fn force_delete_host(
        &self,
        node_id: &str,
        dpu_device_names: &[String],
    ) -> Result<(), DpfError> {
        self.sdk.force_delete_host(node_id, dpu_device_names).await
    }

    async fn reprovision_dpu(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<(), DpfError> {
        self.sdk.reprovision_dpu(dpu_device_name, node_name).await
    }

    async fn get_dpu_phase(
        &self,
        dpu_device_name: &str,
        node_name: &str,
    ) -> Result<DpuPhase, DpfError> {
        self.sdk.get_dpu_phase(dpu_device_name, node_name).await
    }

    async fn is_reboot_required(&self, node_name: &str) -> Result<bool, DpfError> {
        self.sdk.is_reboot_required(node_name).await
    }

    async fn reboot_complete(&self, node_name: &str) -> Result<(), DpfError> {
        self.sdk.reboot_complete(node_name).await
    }

    async fn verify_node_labels(&self, node_name: &str) -> Result<bool, DpfError> {
        self.sdk.verify_node_labels(node_name).await
    }
}

fn bfcfg_context(config: &CarbideConfig) -> HashMap<String, String> {
    let mut context = HashMap::new();
    context.insert(API_URL_KEY.to_string(), API_URL.to_string());
    context.insert(PXE_URL_KEY.to_string(), PXE_URL.to_string());

    let fw_context = tera::Context::new();
    let fw_update =
        tera::Tera::one_off(BF_CFG_FW_UPDATE_TEMPLATE, &fw_context, false).unwrap_or_default();
    context.insert(BMC_FW_UPDATE_KEY.to_string(), fw_update);

    let seconds_since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    context.insert(
        SECONDS_SINCE_EPOCH_KEY.to_string(),
        seconds_since_epoch.to_string(),
    );

    if let Some(vmaas) = config.vmaas_config.as_ref() {
        if let Some(hbn_reps) = vmaas.hbn_reps.as_ref() {
            context.insert(HBN_REPS_KEY.to_string(), hbn_reps.clone());
        }

        if let Some(hbn_sfs) = vmaas.hbn_sfs.as_ref() {
            context.insert(HBN_SFS_KEY.to_string(), hbn_sfs.clone());
        }

        if let Some(bridge) = vmaas.bridging.as_ref() {
            context.insert(
                VF_INTERCEPT_BRIDGE_NAME_KEY.to_string(),
                bridge.vf_intercept_bridge_name.clone(),
            );

            context.insert(
                HOST_INTERCEPT_BRIDGE_NAME_KEY.to_string(),
                bridge.host_intercept_bridge_name.clone(),
            );

            let host_intercept_bridge_port = bridge.host_intercept_bridge_port.clone();
            context.insert(
                HOST_INTERCEPT_HBN_PORT_KEY.to_string(),
                format!("patch-hbn-{host_intercept_bridge_port}"),
            );

            context.insert(
                HOST_INTERCEPT_BRIDGE_PORT_KEY.to_string(),
                host_intercept_bridge_port,
            );

            let vf_intercept_bridge_port = bridge.vf_intercept_bridge_port.clone();
            context.insert(
                VF_INTERCEPT_HBN_PORT_KEY.to_string(),
                format!("patch-hbn-{vf_intercept_bridge_port}"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_PORT_KEY.to_string(),
                vf_intercept_bridge_port,
            );

            let vf_intercept_bridge_sf = bridge.vf_intercept_bridge_sf.clone();
            context.insert(
                VF_INTERCEPT_BRIDGE_SF_REPRESENTOR_KEY.to_string(),
                format!("{vf_intercept_bridge_sf}_r"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_SF_HBN_BRIDGE_REPRESENTOR_KEY.to_string(),
                format!("{vf_intercept_bridge_sf}_if_r"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_SF_KEY.to_string(),
                vf_intercept_bridge_sf,
            );
        }
    }
    context
}

pub fn render_bfcfg(config: &CarbideConfig) -> eyre::Result<String> {
    let context = bfcfg_context(config);
    let tera_context = tera::Context::from_serialize(&context)
        .map_err(|e| eyre::eyre!("Failed to serialize bf.cfg context: {e}"))?;
    tera::Tera::one_off(BF_CFG_TEMPLATE, &tera_context, false)
        .map_err(|e| eyre::eyre!("Failed to render bf.cfg template: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::common::api_fixtures::get_config;

    #[test]
    fn render_bfcfg_succeeds() {
        let config = get_config();
        let rendered = render_bfcfg(&config)
            .expect("render_bfcfg failed — bf.cfg template has unparseable syntax");

        assert!(
            rendered.contains("{{if .OOBNetwork}}"),
            "Go template '{{{{if .OOBNetwork}}}}' should pass through raw"
        );
        assert!(
            rendered.contains("{{.KubeadmJoinCMD}}"),
            "Go template '{{{{.KubeadmJoinCMD}}}}' should pass through raw"
        );
        assert!(
            rendered.contains("https://carbide-api.forge"),
            "Tera variable api_url should be rendered"
        );
        assert!(
            rendered.contains("http://carbide-pxe.forge"),
            "Tera variable pxe_url should be rendered"
        );
    }
}
