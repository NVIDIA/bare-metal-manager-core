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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use forge_secrets::credentials::Credentials;
use librms::protos::rack_manager as rms;
use librms::{RackManagerError, RmsApi};
use mac_address::MacAddress;
use model::component_manager::{
    FirmwareState, NvSwitchComponent, PowerAction, PowerShelfComponent,
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    NvSwitchManager, SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus,
    SwitchPowerStateResult, SwitchSlotAndTrayResult,
};
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager, PowerShelfPowerStateResult,
};
use crate::types::FirmwareUpdateOptions;

/// RMS identity for a device: the node_id and rack_id that RMS needs
/// to address it. Used for both power shelves and switches.
#[derive(Clone)]
struct RmsIdentity {
    node_id: String,
    rack_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RmsTrackedFirmwareJob {
    FirmwareObject(String),
    SwitchSystemImage {
        job_id: String,
        rack_id: String,
        node_id: String,
    },
}

// The direct RMS path matches the rack-maintenance flow and applies production
// firmware artifacts only.
const RMS_FIRMWARE_OBJECT_FIRMWARE_TYPE: &str = "prod";
const RMS_SWITCH_SYSTEM_IMAGE_SOFTWARE_TYPE: &str = "prod";
const RMS_FIRMWARE_OBJECT_HARDWARE_TYPE: &str = "any";
const RMS_NOAUTH_ACCESS_TOKEN: &str = "NOAUTH";

pub struct RmsBackend {
    client: Arc<dyn RmsApi>,
    switch_system_image_client: Option<Arc<dyn RmsSwitchSystemImageStatusApi>>,
    db: PgPool,
    /// Tracks firmware update job IDs keyed by device MAC address.
    firmware_jobs: Mutex<HashMap<MacAddress, Vec<RmsTrackedFirmwareJob>>>,
}

#[async_trait::async_trait]
pub trait RmsSwitchSystemImageStatusApi: Send + Sync + 'static {
    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, RackManagerError>;
}

#[async_trait::async_trait]
impl RmsSwitchSystemImageStatusApi for librms::RackManagerApi {
    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, RackManagerError> {
        Ok(self.client.get_switch_system_image_job_status(cmd).await?)
    }
}

impl std::fmt::Debug for RmsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RmsBackend")
            .field("client", &"<RmsApi>")
            .finish()
    }
}

impl RmsBackend {
    pub fn new(
        client: Arc<dyn RmsApi>,
        switch_system_image_client: Option<Arc<dyn RmsSwitchSystemImageStatusApi>>,
        db: PgPool,
    ) -> Self {
        Self {
            client,
            switch_system_image_client,
            db,
            firmware_jobs: Mutex::new(HashMap::new()),
        }
    }
}

/// Resolve power shelf MAC addresses to RMS identities via the api-db layer.
async fn resolve_power_shelf_identities(
    db: &PgPool,
    macs: &[MacAddress],
) -> Result<HashMap<MacAddress, RmsIdentity>, ComponentManagerError> {
    let rows = db::power_shelf::find_rms_identities_by_macs(db, macs)
        .await
        .map_err(|e| {
            ComponentManagerError::Internal(format!(
                "failed to resolve power shelf RMS identities: {e}"
            ))
        })?;

    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let Some(rack_id) = row.rack_id else {
            tracing::warn!(bmc_mac = %row.bmc_mac_address, "power shelf has no rack_id, skipping");
            continue;
        };
        map.insert(
            row.bmc_mac_address,
            RmsIdentity {
                node_id: row.id,
                rack_id: rack_id.to_string(),
            },
        );
    }
    Ok(map)
}

/// Resolve switch MAC addresses to RMS identities via the api-db layer.
async fn resolve_switch_identities(
    db: &PgPool,
    macs: &[MacAddress],
) -> Result<HashMap<MacAddress, RmsIdentity>, ComponentManagerError> {
    let rows = db::switch::find_rms_identities_by_macs(db, macs)
        .await
        .map_err(|e| {
            ComponentManagerError::Internal(format!("failed to resolve switch RMS identities: {e}"))
        })?;

    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let Some(rack_id) = row.rack_id else {
            tracing::warn!(bmc_mac = %row.bmc_mac_address, "switch has no rack_id, skipping");
            continue;
        };
        map.insert(
            row.bmc_mac_address,
            RmsIdentity {
                node_id: row.id,
                rack_id: rack_id.to_string(),
            },
        );
    }
    Ok(map)
}

fn to_rms_power_operation(action: PowerAction) -> i32 {
    match action {
        PowerAction::On => rms::PowerOperation::PowerOn as i32,
        PowerAction::GracefulShutdown | PowerAction::ForceOff => {
            rms::PowerOperation::PowerOff as i32
        }
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            rms::PowerOperation::PowerReset as i32
        }
    }
}

fn map_rms_firmware_job_state(state: i32) -> FirmwareState {
    match rms::FirmwareJobState::try_from(state) {
        Ok(rms::FirmwareJobState::FwJobQueued) => FirmwareState::Queued,
        Ok(rms::FirmwareJobState::FwJobRunning) => FirmwareState::InProgress,
        Ok(rms::FirmwareJobState::FwJobCompleted) => FirmwareState::Completed,
        Ok(rms::FirmwareJobState::FwJobFailed) => FirmwareState::Failed,
        _ => FirmwareState::Unknown,
    }
}

fn map_rms_switch_system_image_job_state(state: &str) -> FirmwareState {
    match state.to_ascii_lowercase().as_str() {
        "queued" | "pending" => FirmwareState::Queued,
        "running" | "in_progress" | "active" => FirmwareState::InProgress,
        "verifying" | "verify" | "validating" | "validation" => FirmwareState::Verifying,
        "completed" | "success" | "done" => FirmwareState::Completed,
        "failed" | "error" => FirmwareState::Failed,
        "cancelled" | "canceled" => FirmwareState::Cancelled,
        _ => FirmwareState::Unknown,
    }
}

fn aggregate_firmware_job_states(states: &[FirmwareState]) -> FirmwareState {
    if states.is_empty() {
        return FirmwareState::Unknown;
    }
    if states.contains(&FirmwareState::Failed) {
        return FirmwareState::Failed;
    }
    if states.contains(&FirmwareState::Cancelled) {
        return FirmwareState::Cancelled;
    }
    if states.contains(&FirmwareState::InProgress) {
        return FirmwareState::InProgress;
    }
    if states.contains(&FirmwareState::Verifying) {
        return FirmwareState::Verifying;
    }
    if states.contains(&FirmwareState::Queued) {
        return FirmwareState::Queued;
    }
    if states.contains(&FirmwareState::Unknown) {
        return FirmwareState::Unknown;
    }
    if states
        .iter()
        .all(|state| *state == FirmwareState::Completed)
    {
        FirmwareState::Completed
    } else {
        FirmwareState::Unknown
    }
}

/// Default BMC HTTPS port used when populating `rms::BmcEndpoint` for power
/// shelves. Mirrors the value used by `crate::power_shelf_controller::maintenance`.
const POWER_SHELF_BMC_PORT: i32 = 443;

/// Build the `rms::NewNodeInfo` describing a power shelf for inclusion in a
/// `SetPowerStateByDeviceList` request. The caller-supplied variant of the
/// RPC requires the BMC connection details inline rather than relying on
/// RMS's inventory; power shelves do not expose a host endpoint.
fn build_power_shelf_node_info(
    ep: &PowerShelfEndpoint,
    identity: &RmsIdentity,
) -> rms::NewNodeInfo {
    rms::NewNodeInfo {
        node_id: identity.node_id.clone(),
        rack_id: identity.rack_id.clone(),
        r#type: Some(rms::NodeType::Powershelf as i32),
        bmc_endpoint: Some(rms::BmcEndpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.pmc_ip.to_string(),
                mac_address: ep.pmc_mac.to_string(),
            }),
            port: POWER_SHELF_BMC_PORT,
            credentials: Some(credentials_to_rms(&ep.pmc_credentials)),
        }),
        host_endpoint: None,
    }
}

#[async_trait::async_trait]
impl PowerShelfManager for RmsBackend {
    fn name(&self) -> &str {
        "rms"
    }

    fn supports_firmware_object_json(&self) -> bool {
        true
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn power_control(
        &self,
        endpoints: &[PowerShelfEndpoint],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let ids = resolve_power_shelf_identities(&self.db, &macs).await?;
        let operation = to_rms_power_operation(action);
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.pmc_mac) else {
                results.push(PowerShelfComponentResult {
                    pmc_mac: ep.pmc_mac,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_power_shelf_node_info(ep, identity);
            let request = rms::SetPowerStateByDeviceListRequest {
                nodes: Some(rms::NodeSet {
                    devices: vec![device],
                }),
                operation,
                ..Default::default()
            };

            match self.client.set_power_state_by_device_list(request).await {
                Ok(response) => {
                    let (success, error) =
                        summarize_power_batch(response.response.unwrap_or_default());
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success,
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        pmc_mac = %ep.pmc_mac,
                        error = %e,
                        "RMS power control failed for power shelf"
                    );
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    #[instrument(skip(self, target_version, options), fields(backend = "rms", force_update = options.force_update))]
    async fn update_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
        target_version: &str,
        components: &[PowerShelfComponent],
        options: &FirmwareUpdateOptions,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let ids = resolve_power_shelf_identities(&self.db, &macs).await?;
        let component_filters = power_shelf_firmware_object_component_filters(components);

        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.pmc_mac) else {
                results.push(PowerShelfComponentResult {
                    pmc_mac: ep.pmc_mac,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_power_shelf_node_info(ep, identity);
            let request = match apply_firmware_object_from_json_request(
                device,
                identity,
                target_version,
                options,
                rms::NodeType::Powershelf,
                component_filters.clone(),
            ) {
                Ok(request) => request,
                Err(e) => {
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: false,
                        error: Some(e.to_string()),
                    });
                    continue;
                }
            };

            match self.client.apply_firmware_object_from_json(request).await {
                Ok(response) => {
                    let (success, error, job_id) =
                        summarize_firmware_object_apply_response(response, &identity.node_id);

                    if success {
                        if let Some(job_id) = job_id {
                            self.firmware_jobs.lock().unwrap().insert(
                                ep.pmc_mac,
                                vec![RmsTrackedFirmwareJob::FirmwareObject(job_id)],
                            );
                        } else {
                            self.firmware_jobs.lock().unwrap().remove(&ep.pmc_mac);
                        }
                    } else {
                        self.firmware_jobs.lock().unwrap().remove(&ep.pmc_mac);
                    }

                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success,
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        pmc_mac = %ep.pmc_mac,
                        error = %e,
                        "RMS firmware update failed for power shelf"
                    );
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_firmware_status(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        // Snapshot job IDs under the lock, then release it before making
        // async RMS calls (avoids holding a std::sync::Mutex across await).
        let endpoint_jobs: Vec<(MacAddress, Option<String>)> = {
            let jobs = self.firmware_jobs.lock().unwrap();
            endpoints
                .iter()
                .map(|ep| {
                    let job_id = jobs.get(&ep.pmc_mac).and_then(|jobs| {
                        jobs.iter().find_map(|job| match job {
                            RmsTrackedFirmwareJob::FirmwareObject(job_id) => Some(job_id.clone()),
                            RmsTrackedFirmwareJob::SwitchSystemImage { .. } => None,
                        })
                    });
                    (ep.pmc_mac, job_id)
                })
                .collect()
        };

        let mut statuses = Vec::with_capacity(endpoints.len());

        for (pmc_mac, job_id) in &endpoint_jobs {
            let Some(job_id) = job_id else {
                statuses.push(PowerShelfFirmwareUpdateStatus {
                    pmc_mac: *pmc_mac,
                    state: FirmwareState::Unknown,
                    target_version: String::new(),
                    error: Some("no firmware job tracked for this power shelf".into()),
                });
                continue;
            };

            let request = rms::GetFirmwareJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            };

            match self.client.get_firmware_job_status(request).await {
                Ok(response) => {
                    let status_success = response.status == rms::ReturnCode::Success as i32;
                    let state = if status_success {
                        map_rms_firmware_job_state(response.job_state)
                    } else {
                        FirmwareState::Unknown
                    };
                    let error = if response.error_message.is_empty() {
                        (!status_success).then(|| {
                            format!("RMS could not report status for firmware job {job_id}")
                        })
                    } else {
                        Some(response.error_message)
                    };
                    statuses.push(PowerShelfFirmwareUpdateStatus {
                        pmc_mac: *pmc_mac,
                        state,
                        target_version: String::new(),
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        pmc_mac = %pmc_mac,
                        job_id = %job_id,
                        error = %e,
                        "RMS firmware job status query failed"
                    );
                    statuses.push(PowerShelfFirmwareUpdateStatus {
                        pmc_mac: *pmc_mac,
                        state: FirmwareState::Unknown,
                        target_version: String::new(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(statuses)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn list_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareVersions>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let ids = resolve_power_shelf_identities(&self.db, &macs).await?;
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.pmc_mac) else {
                results.push(PowerShelfFirmwareVersions {
                    pmc_mac: ep.pmc_mac,
                    versions: vec![],
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let request = rms::GetNodeFirmwareInventoryRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
                ..Default::default()
            };

            match self.client.get_node_firmware_inventory(request).await {
                Ok(response) => {
                    if response.status != rms::ReturnCode::Success as i32 {
                        results.push(PowerShelfFirmwareVersions {
                            pmc_mac: ep.pmc_mac,
                            versions: vec![],
                            error: Some("RMS firmware inventory query failed".into()),
                        });
                        continue;
                    }

                    let versions = response
                        .firmware_list
                        .into_iter()
                        .map(|fi| fi.version)
                        .collect();

                    results.push(PowerShelfFirmwareVersions {
                        pmc_mac: ep.pmc_mac,
                        versions,
                        error: None,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        pmc_mac = %ep.pmc_mac,
                        error = %e,
                        "RMS firmware inventory query failed for power shelf"
                    );
                    results.push(PowerShelfFirmwareVersions {
                        pmc_mac: ep.pmc_mac,
                        versions: vec![],
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_power_state(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfPowerStateResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let ids = resolve_power_shelf_identities(&self.db, &macs).await?;
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.pmc_mac) else {
                results.push(PowerShelfPowerStateResult {
                    pmc_mac: ep.pmc_mac,
                    power_state: None,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_power_shelf_node_info(ep, identity);
            let observed = query_rms_power_state(
                self.client.as_ref(),
                device,
                &identity.node_id,
                ep.pmc_mac,
                "power shelf",
            )
            .await;
            results.push(PowerShelfPowerStateResult {
                pmc_mac: ep.pmc_mac,
                power_state: observed.power_state,
                error: observed.error,
            });
        }

        Ok(results)
    }
}

/// Query all firmware object IDs from RMS.
async fn list_firmware_object_ids(
    client: &dyn RmsApi,
) -> Result<Vec<String>, ComponentManagerError> {
    let response = client
        .list_firmware_objects(rms::ListFirmwareObjectsRequest {
            metadata: None,
            only_available: false,
            hardware_type: String::new(),
        })
        .await
        .map_err(|e| {
            ComponentManagerError::Internal(format!(
                "failed to list firmware objects from RMS: {e}"
            ))
        })?;

    Ok(response.objects.into_iter().map(|fw| fw.id).collect())
}

/// Default BMC HTTPS port used when populating `rms::BmcEndpoint` for
/// switches. Mirrors the value used by `crate::rack::firmware_update`.
const SWITCH_BMC_PORT: i32 = 443;

fn credentials_to_rms(creds: &Credentials) -> rms::Credentials {
    let Credentials::UsernamePassword { username, password } = creds;
    rms::Credentials {
        auth: Some(rms::credentials::Auth::UserPass(rms::UsernamePassword {
            username: username.clone(),
            password: password.clone(),
        })),
    }
}

/// Build the `rms::NewNodeInfo` describing a switch for inclusion in a
/// `SetPowerStateByDeviceList` request. The caller-supplied variant of the
/// RPC requires the BMC connection details inline rather than relying on
/// RMS's inventory; the NVOS host endpoint is included for completeness.
fn build_switch_node_info(ep: &SwitchEndpoint, identity: &RmsIdentity) -> rms::NewNodeInfo {
    rms::NewNodeInfo {
        node_id: identity.node_id.clone(),
        rack_id: identity.rack_id.clone(),
        r#type: Some(rms::NodeType::Switch as i32),
        bmc_endpoint: Some(rms::BmcEndpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.bmc_ip.to_string(),
                mac_address: ep.bmc_mac.to_string(),
            }),
            port: SWITCH_BMC_PORT,
            credentials: Some(credentials_to_rms(&ep.bmc_credentials)),
        }),
        host_endpoint: Some(rms::HostEndpoint {
            interfaces: vec![rms::NetworkInterface {
                ip_address: ep.nvos_ip.to_string(),
                mac_address: ep.nvos_mac.to_string(),
            }],
            port: 0,
            credentials: Some(credentials_to_rms(&ep.nvos_credentials)),
        }),
    }
}

/// Summarize a `NodeBatchResponse` into a `(success, error)` pair for a
/// single-device `SetPowerStateByDeviceList` call. Prefers per-node error
/// messages, then the batch-level message, and finally a generic fallback.
fn summarize_power_batch(batch: rms::NodeBatchResponse) -> (bool, Option<String>) {
    let success = batch.status == rms::ReturnCode::Success as i32 && batch.failed_nodes == 0;
    if success {
        return (true, None);
    }

    let node_error = batch
        .node_results
        .into_iter()
        .find(|r| r.status != rms::ReturnCode::Success as i32 || !r.error_message.is_empty())
        .and_then(|r| {
            if r.error_message.is_empty() {
                None
            } else {
                Some(r.error_message)
            }
        });

    let error = node_error
        .or({
            if batch.message.is_empty() {
                None
            } else {
                Some(batch.message)
            }
        })
        .unwrap_or_else(|| "RMS power control failed".to_owned());

    (false, Some(error))
}

#[derive(Debug, Clone)]
struct RmsObservedPowerState {
    power_state: Option<String>,
    error: Option<String>,
}

async fn query_rms_power_state(
    client: &dyn RmsApi,
    device: rms::NewNodeInfo,
    node_id: &str,
    device_mac: MacAddress,
    device_kind: &str,
) -> RmsObservedPowerState {
    let request = rms::GetPowerStateByDeviceListRequest {
        nodes: Some(rms::NodeSet {
            devices: vec![device],
        }),
        ..Default::default()
    };

    match client.get_power_state_by_device_list(request).await {
        Ok(response) => {
            let batch = response.response.clone().unwrap_or_default();
            if batch.status != rms::ReturnCode::Success as i32 || batch.failed_nodes != 0 {
                let summary = if batch.message.is_empty() {
                    format!(
                        "batch status {}, failed_nodes {}",
                        batch.status, batch.failed_nodes
                    )
                } else {
                    batch.message
                };
                return RmsObservedPowerState {
                    power_state: None,
                    error: Some(summary),
                };
            }

            let power_state = response
                .node_power_states
                .iter()
                .find(|node| node.node_id == node_id)
                .map(|node| node.pstate.to_lowercase());

            RmsObservedPowerState {
                power_state,
                error: None,
            }
        }
        Err(error) => {
            tracing::warn!(
                %device_mac,
                error = %error,
                device_kind,
                "RMS get power state failed"
            );
            RmsObservedPowerState {
                power_state: None,
                error: Some(error.to_string()),
            }
        }
    }
}

fn rms_access_token_or_noauth(access_token: Option<&str>) -> String {
    access_token
        .filter(|token| !token.trim().is_empty())
        .unwrap_or(RMS_NOAUTH_ACCESS_TOKEN)
        .to_string()
}

fn apply_firmware_object_from_json_request(
    device: rms::NewNodeInfo,
    identity: &RmsIdentity,
    config_json: &str,
    options: &FirmwareUpdateOptions,
    node_type: rms::NodeType,
    components: Vec<String>,
) -> Result<rms::ApplyFirmwareObjectFromJsonRequest, ComponentManagerError> {
    let access_token = rms_access_token_or_noauth(options.access_token.as_deref());

    if config_json.trim().is_empty() {
        return Err(ComponentManagerError::InvalidArgument(
            "target_version must contain firmware-object JSON for direct RMS updates".into(),
        ));
    }

    let mut component_filters = HashMap::with_capacity(1);
    component_filters.insert(
        node_type as i32,
        rms::FirmwareObjectComponentFilter { components },
    );

    Ok(rms::ApplyFirmwareObjectFromJsonRequest {
        metadata: None,
        rack_id: identity.rack_id.clone(),
        config_json: config_json.to_owned(),
        access_token,
        firmware_type: RMS_FIRMWARE_OBJECT_FIRMWARE_TYPE.to_owned(),
        hardware_type: RMS_FIRMWARE_OBJECT_HARDWARE_TYPE.to_owned(),
        nodes: Some(rms::NodeSet {
            devices: vec![device],
        }),
        force_update: options.force_update,
        component_filters,
    })
}

fn apply_switch_system_image_from_json_request(
    device: rms::NewNodeInfo,
    identity: &RmsIdentity,
    config_json: &str,
    options: &FirmwareUpdateOptions,
) -> Result<rms::ApplySwitchSystemImageFromJsonRequest, ComponentManagerError> {
    let access_token = rms_access_token_or_noauth(options.access_token.as_deref());

    if config_json.trim().is_empty() {
        return Err(ComponentManagerError::InvalidArgument(
            "target_version must contain firmware-object JSON for direct RMS updates".into(),
        ));
    }

    Ok(rms::ApplySwitchSystemImageFromJsonRequest {
        metadata: None,
        rack_id: identity.rack_id.clone(),
        config_json: config_json.to_owned(),
        access_token,
        software_type: RMS_SWITCH_SYSTEM_IMAGE_SOFTWARE_TYPE.to_owned(),
        hardware_type: RMS_FIRMWARE_OBJECT_HARDWARE_TYPE.to_owned(),
        nodes: Some(rms::NodeSet {
            devices: vec![device],
        }),
        // RMS does not expose force_update on switch system-image JSON updates.
    })
}

fn power_shelf_firmware_object_component_filters(
    components: &[PowerShelfComponent],
) -> Vec<String> {
    if components.is_empty() {
        Vec::new()
    } else {
        vec!["PowerShelfFW".to_owned()]
    }
}

fn switch_update_includes_firmware_object(components: &[NvSwitchComponent]) -> bool {
    components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, NvSwitchComponent::Nvos))
}

fn switch_update_includes_system_image(components: &[NvSwitchComponent]) -> bool {
    components.is_empty()
        || components
            .iter()
            .any(|component| matches!(component, NvSwitchComponent::Nvos))
}

fn switch_firmware_object_component_filters(components: &[NvSwitchComponent]) -> Vec<String> {
    components
        .iter()
        .filter_map(|c| match c {
            NvSwitchComponent::Bmc => Some("BMC".to_owned()),
            NvSwitchComponent::Cpld => Some("CPLD".to_owned()),
            NvSwitchComponent::Bios => Some("BIOS".to_owned()),
            NvSwitchComponent::Nvos => None,
        })
        .collect()
}

fn summarize_firmware_object_apply_response(
    response: rms::ApplyFirmwareObjectResponse,
    node_id: &str,
) -> (bool, Option<String>, Option<String>) {
    let node_job_id = response
        .node_jobs
        .iter()
        .find(|j| j.node_id == node_id && !j.job_id.is_empty())
        .map(|j| j.job_id.clone());

    summarize_firmware_batch(
        response.response,
        node_job_id,
        node_id,
        "RMS firmware update failed",
    )
}

fn summarize_switch_system_image_apply_response(
    response: rms::ApplySwitchSystemImageResponse,
    node_id: &str,
) -> (bool, Option<String>, Option<String>) {
    let node_job_id = response
        .node_jobs
        .iter()
        .find(|j| j.node_id == node_id && !j.job_id.is_empty())
        .map(|j| j.job_id.clone());

    summarize_firmware_batch(
        response.response,
        node_job_id,
        node_id,
        "RMS switch system image update failed",
    )
}

fn summarize_firmware_batch(
    batch: Option<rms::NodeBatchResponse>,
    node_job_id: Option<String>,
    node_id: &str,
    default_error: &str,
) -> (bool, Option<String>, Option<String>) {
    let Some(batch) = batch else {
        return (false, Some(default_error.to_owned()), node_job_id);
    };
    let node_failure = batch
        .node_results
        .iter()
        .find(|r| r.node_id == node_id && r.status != rms::ReturnCode::Success as i32)
        .or_else(|| {
            batch
                .node_results
                .iter()
                .find(|r| r.status != rms::ReturnCode::Success as i32)
        });
    let success = batch.status == rms::ReturnCode::Success as i32
        && batch.failed_nodes == 0
        && node_failure.is_none();
    let job_id = node_job_id.or_else(|| (!batch.job_id.is_empty()).then_some(batch.job_id.clone()));

    if success {
        return (true, None, job_id);
    }

    let error = node_failure
        .and_then(|r| {
            if r.error_message.is_empty() {
                None
            } else {
                Some(r.error_message.clone())
            }
        })
        .or({
            if batch.message.is_empty() {
                None
            } else {
                Some(batch.message)
            }
        })
        .unwrap_or_else(|| default_error.to_owned());

    (false, Some(error), job_id)
}

async fn query_tracked_firmware_job_status(
    client: &dyn RmsApi,
    switch_system_image_client: Option<&dyn RmsSwitchSystemImageStatusApi>,
    job: &RmsTrackedFirmwareJob,
) -> (FirmwareState, Option<String>) {
    match job {
        RmsTrackedFirmwareJob::FirmwareObject(job_id) => {
            let request = rms::GetFirmwareJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            };

            match client.get_firmware_job_status(request).await {
                Ok(response) => {
                    let status_success = response.status == rms::ReturnCode::Success as i32;
                    let state = if status_success {
                        map_rms_firmware_job_state(response.job_state)
                    } else {
                        FirmwareState::Unknown
                    };
                    let error = if response.error_message.is_empty() {
                        (!status_success).then(|| {
                            format!("RMS could not report status for firmware job {job_id}")
                        })
                    } else {
                        Some(response.error_message)
                    };
                    (state, error)
                }
                Err(e) => (FirmwareState::Unknown, Some(e.to_string())),
            }
        }
        RmsTrackedFirmwareJob::SwitchSystemImage {
            job_id,
            rack_id: _,
            node_id: _,
        } => {
            let Some(client) = switch_system_image_client else {
                return (
                    FirmwareState::Unknown,
                    Some("RMS switch system-image status client is not configured".to_owned()),
                );
            };
            let request = rms::GetSwitchSystemImageJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            };

            match client.get_switch_system_image_job_status(request).await {
                Ok(response) if response.status == rms::ReturnCode::Success as i32 => {
                    let state = map_rms_switch_system_image_job_state(&response.state);
                    let error = if response.error_message.is_empty() {
                        (!response.message.is_empty()
                            && matches!(state, FirmwareState::Failed | FirmwareState::Unknown))
                        .then_some(response.message)
                    } else {
                        Some(response.error_message)
                    };
                    (state, error)
                }
                Ok(response) => {
                    let error = if response.error_message.is_empty() {
                        if response.message.is_empty() {
                            format!(
                                "RMS could not report status for switch system-image job {job_id}"
                            )
                        } else {
                            response.message
                        }
                    } else {
                        response.error_message
                    };
                    (FirmwareState::Unknown, Some(error))
                }
                Err(e) => (FirmwareState::Unknown, Some(e.to_string())),
            }
        }
    }
}

#[async_trait::async_trait]
impl NvSwitchManager for RmsBackend {
    fn name(&self) -> &str {
        "rms"
    }

    fn supports_firmware_object_json(&self) -> bool {
        true
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let ids = resolve_switch_identities(&self.db, &macs).await?;
        let operation = to_rms_power_operation(action);
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_mac) else {
                results.push(SwitchComponentResult {
                    bmc_mac: ep.bmc_mac,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_switch_node_info(ep, identity);
            let request = rms::SetPowerStateByDeviceListRequest {
                nodes: Some(rms::NodeSet {
                    devices: vec![device],
                }),
                operation,
                ..Default::default()
            };

            match self.client.set_power_state_by_device_list(request).await {
                Ok(response) => {
                    let (success, error) =
                        summarize_power_batch(response.response.unwrap_or_default());
                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success,
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_mac = %ep.bmc_mac,
                        error = %e,
                        "RMS power control failed for switch"
                    );
                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    #[instrument(skip(self, bundle_version, options), fields(backend = "rms", force_update = options.force_update))]
    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        components: &[NvSwitchComponent],
        options: &FirmwareUpdateOptions,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let ids = resolve_switch_identities(&self.db, &macs).await?;
        let include_firmware_object = switch_update_includes_firmware_object(components);
        let include_system_image = switch_update_includes_system_image(components);
        let component_filters = switch_firmware_object_component_filters(components);

        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_mac) else {
                results.push(SwitchComponentResult {
                    bmc_mac: ep.bmc_mac,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let mut success = true;
            let mut errors = Vec::new();
            let mut tracked_jobs = Vec::new();

            if include_firmware_object {
                let device = build_switch_node_info(ep, identity);
                match apply_firmware_object_from_json_request(
                    device,
                    identity,
                    bundle_version,
                    options,
                    rms::NodeType::Switch,
                    component_filters.clone(),
                ) {
                    Ok(request) => match self.client.apply_firmware_object_from_json(request).await
                    {
                        Ok(response) => {
                            let (operation_success, error, job_id) =
                                summarize_firmware_object_apply_response(
                                    response,
                                    &identity.node_id,
                                );

                            if !operation_success {
                                success = false;
                            }
                            if let Some(error) = error {
                                errors.push(error);
                            }
                            if operation_success {
                                if let Some(job_id) = job_id {
                                    tracked_jobs
                                        .push(RmsTrackedFirmwareJob::FirmwareObject(job_id));
                                }
                            } else if job_id.is_some() {
                                tracing::debug!(
                                    bmc_mac = %ep.bmc_mac,
                                    "RMS returned a firmware-object job id for a failed switch update; not tracking it"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                bmc_mac = %ep.bmc_mac,
                                error = %e,
                                "RMS firmware-object update failed for switch"
                            );
                            success = false;
                            errors.push(e.to_string());
                        }
                    },
                    Err(e) => {
                        success = false;
                        errors.push(e.to_string());
                    }
                }
            }

            if include_system_image {
                let device = build_switch_node_info(ep, identity);
                match apply_switch_system_image_from_json_request(
                    device,
                    identity,
                    bundle_version,
                    options,
                ) {
                    Ok(request) => {
                        match self
                            .client
                            .apply_switch_system_image_from_json(request)
                            .await
                        {
                            Ok(response) => {
                                let (operation_success, error, job_id) =
                                    summarize_switch_system_image_apply_response(
                                        response,
                                        &identity.node_id,
                                    );

                                if !operation_success {
                                    success = false;
                                }
                                if let Some(error) = error {
                                    errors.push(error);
                                }
                                if operation_success {
                                    if let Some(job_id) = job_id {
                                        tracked_jobs.push(
                                            RmsTrackedFirmwareJob::SwitchSystemImage {
                                                job_id,
                                                rack_id: identity.rack_id.clone(),
                                                node_id: identity.node_id.clone(),
                                            },
                                        );
                                    }
                                } else if job_id.is_some() {
                                    tracing::debug!(
                                        bmc_mac = %ep.bmc_mac,
                                        "RMS returned a switch system-image job id for a failed switch update; not tracking it"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    bmc_mac = %ep.bmc_mac,
                                    error = %e,
                                    "RMS switch system-image update failed for switch"
                                );
                                success = false;
                                errors.push(e.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        success = false;
                        errors.push(e.to_string());
                    }
                }
            }

            if !tracked_jobs.is_empty() {
                self.firmware_jobs
                    .lock()
                    .unwrap()
                    .insert(ep.bmc_mac, tracked_jobs);
            } else {
                self.firmware_jobs.lock().unwrap().remove(&ep.bmc_mac);
            }

            results.push(SwitchComponentResult {
                bmc_mac: ep.bmc_mac,
                success,
                error: (!errors.is_empty()).then(|| errors.join("; ")),
            });
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        let endpoint_jobs: Vec<(MacAddress, Vec<RmsTrackedFirmwareJob>)> = {
            let jobs = self.firmware_jobs.lock().unwrap();
            endpoints
                .iter()
                .map(|ep| {
                    (
                        ep.bmc_mac,
                        jobs.get(&ep.bmc_mac).cloned().unwrap_or_default(),
                    )
                })
                .collect()
        };

        let mut statuses = Vec::with_capacity(endpoints.len());

        for (bmc_mac, jobs) in &endpoint_jobs {
            if jobs.is_empty() {
                statuses.push(SwitchFirmwareUpdateStatus {
                    bmc_mac: *bmc_mac,
                    state: FirmwareState::Unknown,
                    target_version: String::new(),
                    error: Some("no firmware job tracked for this switch".into()),
                });
                continue;
            }

            let mut states = Vec::with_capacity(jobs.len());
            let mut errors = Vec::new();
            for job in jobs {
                let (state, error) = query_tracked_firmware_job_status(
                    self.client.as_ref(),
                    self.switch_system_image_client.as_deref(),
                    job,
                )
                .await;
                states.push(state);
                if let Some(error) = error {
                    errors.push(error);
                }
            }

            statuses.push(SwitchFirmwareUpdateStatus {
                bmc_mac: *bmc_mac,
                state: aggregate_firmware_job_states(&states),
                target_version: String::new(),
                error: (!errors.is_empty()).then(|| errors.join("; ")),
            });
        }

        Ok(statuses)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        list_firmware_object_ids(self.client.as_ref()).await
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_power_state(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchPowerStateResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let ids = resolve_switch_identities(&self.db, &macs).await?;
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_mac) else {
                results.push(SwitchPowerStateResult {
                    bmc_mac: ep.bmc_mac,
                    power_state: None,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_switch_node_info(ep, identity);
            let observed = query_rms_power_state(
                self.client.as_ref(),
                device,
                &identity.node_id,
                ep.bmc_mac,
                "switch",
            )
            .await;
            results.push(SwitchPowerStateResult {
                bmc_mac: ep.bmc_mac,
                power_state: observed.power_state,
                error: observed.error,
            });
        }

        Ok(results)
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_slot_and_tray(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchSlotAndTrayResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let ids = resolve_switch_identities(&self.db, &macs).await?;
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_mac) else {
                results.push(SwitchSlotAndTrayResult {
                    bmc_mac: ep.bmc_mac,
                    slot_number: None,
                    tray_index: None,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let device = build_switch_node_info(ep, identity);
            let request = rms::GetDeviceInfoByDeviceListRequest {
                nodes: Some(rms::NodeSet {
                    devices: vec![device],
                }),
                ..Default::default()
            };

            match self.client.get_device_info_by_device_list(request).await {
                Ok(info) => {
                    if info.status != rms::ReturnCode::Success as i32 {
                        let summary = if info.message.is_empty() {
                            format!("status {}", info.status)
                        } else {
                            info.message.clone()
                        };
                        results.push(SwitchSlotAndTrayResult {
                            bmc_mac: ep.bmc_mac,
                            slot_number: None,
                            tray_index: None,
                            error: Some(summary),
                        });
                        continue;
                    }

                    let Some(node_device_info) = info.node_device_info.first() else {
                        results.push(SwitchSlotAndTrayResult {
                            bmc_mac: ep.bmc_mac,
                            slot_number: None,
                            tray_index: None,
                            error: None,
                        });
                        continue;
                    };

                    results.push(SwitchSlotAndTrayResult {
                        bmc_mac: ep.bmc_mac,
                        slot_number: node_device_info.slot_number,
                        tray_index: node_device_info.tray_index,
                        error: None,
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        bmc_mac = %ep.bmc_mac,
                        error = %error,
                        "RMS get slot and tray failed for switch"
                    );
                    results.push(SwitchSlotAndTrayResult {
                        bmc_mac: ep.bmc_mac,
                        slot_number: None,
                        tray_index: None,
                        error: Some(error.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use api_test_helper::mock_rms::MockRmsApi;
    use carbide_uuid::power_shelf::PowerShelfId;
    use carbide_uuid::rack::RackId;
    use carbide_uuid::switch::SwitchId;

    use super::*;
    use crate::power_shelf_manager::PowerShelfVendor;

    #[async_trait::async_trait]
    impl RmsSwitchSystemImageStatusApi for MockRmsApi {
        async fn get_switch_system_image_job_status(
            &self,
            cmd: rms::GetSwitchSystemImageJobStatusRequest,
        ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, RackManagerError> {
            self.get_switch_system_image_job_status_for_test(cmd).await
        }
    }
    use crate::test_support::{
        PS_MAC_1, PS_MAC_2, SW_MAC_1, SW_MAC_2, UNKNOWN_MAC, seed_test_data,
    };

    // ---- Mapping unit tests ----

    #[test]
    fn power_action_on_maps_to_power_on() {
        assert_eq!(
            to_rms_power_operation(PowerAction::On),
            rms::PowerOperation::PowerOn as i32,
        );
    }

    #[test]
    fn power_action_shutdown_maps_to_power_off() {
        assert_eq!(
            to_rms_power_operation(PowerAction::GracefulShutdown),
            rms::PowerOperation::PowerOff as i32,
        );
    }

    #[test]
    fn power_action_force_off_maps_to_power_off() {
        assert_eq!(
            to_rms_power_operation(PowerAction::ForceOff),
            rms::PowerOperation::PowerOff as i32,
        );
    }

    #[test]
    fn power_action_restart_maps_to_power_reset() {
        for action in [
            PowerAction::GracefulRestart,
            PowerAction::ForceRestart,
            PowerAction::AcPowercycle,
        ] {
            assert_eq!(
                to_rms_power_operation(action),
                rms::PowerOperation::PowerReset as i32,
                "expected PowerReset for {action:?}",
            );
        }
    }

    #[test]
    fn firmware_job_state_queued() {
        assert_eq!(
            map_rms_firmware_job_state(rms::FirmwareJobState::FwJobQueued as i32),
            FirmwareState::Queued,
        );
    }

    #[test]
    fn firmware_job_state_running() {
        assert_eq!(
            map_rms_firmware_job_state(rms::FirmwareJobState::FwJobRunning as i32),
            FirmwareState::InProgress,
        );
    }

    #[test]
    fn firmware_job_state_completed() {
        assert_eq!(
            map_rms_firmware_job_state(rms::FirmwareJobState::FwJobCompleted as i32),
            FirmwareState::Completed,
        );
    }

    #[test]
    fn firmware_job_state_failed() {
        assert_eq!(
            map_rms_firmware_job_state(rms::FirmwareJobState::FwJobFailed as i32),
            FirmwareState::Failed,
        );
    }

    #[test]
    fn firmware_job_state_unknown_for_unrecognized_value() {
        assert_eq!(map_rms_firmware_job_state(9999), FirmwareState::Unknown);
    }

    #[test]
    fn switch_system_image_job_state_maps_cancelled_and_verifying() {
        assert_eq!(
            map_rms_switch_system_image_job_state("cancelled"),
            FirmwareState::Cancelled,
        );
        assert_eq!(
            map_rms_switch_system_image_job_state("verifying"),
            FirmwareState::Verifying,
        );
    }

    #[test]
    fn aggregate_firmware_job_states_prioritizes_active_over_unknown() {
        assert_eq!(
            aggregate_firmware_job_states(&[
                FirmwareState::Completed,
                FirmwareState::Unknown,
                FirmwareState::InProgress,
            ]),
            FirmwareState::InProgress,
        );
        assert_eq!(
            aggregate_firmware_job_states(&[
                FirmwareState::Completed,
                FirmwareState::Queued,
                FirmwareState::Unknown,
            ]),
            FirmwareState::Queued,
        );
    }

    #[test]
    fn aggregate_firmware_job_states_terminal_failures_win() {
        assert_eq!(
            aggregate_firmware_job_states(&[
                FirmwareState::Failed,
                FirmwareState::InProgress,
                FirmwareState::Unknown,
            ]),
            FirmwareState::Failed,
        );
        assert_eq!(
            aggregate_firmware_job_states(&[
                FirmwareState::Cancelled,
                FirmwareState::InProgress,
                FirmwareState::Unknown,
            ]),
            FirmwareState::Cancelled,
        );
    }

    #[test]
    fn power_shelf_firmware_object_filter_collapses_components() {
        let filters = power_shelf_firmware_object_component_filters(&[
            PowerShelfComponent::Pmc,
            PowerShelfComponent::Psu,
        ]);

        assert_eq!(filters, ["PowerShelfFW"]);
    }

    #[test]
    fn switch_firmware_object_filters_map_supported_components() {
        let filters = switch_firmware_object_component_filters(&[
            NvSwitchComponent::Bmc,
            NvSwitchComponent::Cpld,
            NvSwitchComponent::Bios,
        ]);

        assert_eq!(filters, ["BMC", "CPLD", "BIOS"]);
    }

    #[test]
    fn switch_firmware_object_filters_skip_nvos() {
        let filters = switch_firmware_object_component_filters(&[
            NvSwitchComponent::Bmc,
            NvSwitchComponent::Nvos,
        ]);

        assert_eq!(filters, ["BMC"]);
        assert!(switch_update_includes_firmware_object(&[
            NvSwitchComponent::Bmc,
            NvSwitchComponent::Nvos,
        ]));
        assert!(switch_update_includes_system_image(&[
            NvSwitchComponent::Bmc,
            NvSwitchComponent::Nvos,
        ]));
    }

    #[test]
    fn switch_empty_component_list_updates_firmware_object_and_system_image() {
        assert!(switch_update_includes_firmware_object(&[]));
        assert!(switch_update_includes_system_image(&[]));
        assert!(switch_firmware_object_component_filters(&[]).is_empty());
    }

    #[test]
    fn firmware_update_missing_batch_response_is_failure() {
        let response = rms::ApplyFirmwareObjectResponse {
            response: None,
            object_id: "fw-json".to_owned(),
            node_jobs: vec![rms::NodeFirmwareJobInfo {
                node_id: "node-1".to_owned(),
                job_id: "job-1".to_owned(),
            }],
        };

        let (success, error, job_id) = summarize_firmware_object_apply_response(response, "node-1");

        assert!(!success);
        assert_eq!(error.as_deref(), Some("RMS firmware update failed"));
        assert_eq!(job_id.as_deref(), Some("job-1"));
    }

    // ---- Test helpers ----

    fn make_ps_endpoint(mac: &str) -> PowerShelfEndpoint {
        use forge_secrets::credentials::Credentials;
        PowerShelfEndpoint {
            pmc_ip: "10.0.0.1".parse().unwrap(),
            pmc_mac: mac.parse().unwrap(),
            pmc_vendor: PowerShelfVendor::Liteon,
            pmc_credentials: Credentials::UsernamePassword {
                username: "admin".into(),
                password: "pass".into(),
            },
        }
    }

    fn make_sw_endpoint(mac: &str) -> SwitchEndpoint {
        use forge_secrets::credentials::Credentials;
        SwitchEndpoint {
            bmc_ip: "10.0.0.1".parse().unwrap(),
            bmc_mac: mac.parse().unwrap(),
            nvos_ip: "10.0.0.2".parse().unwrap(),
            nvos_mac: "11:22:33:44:55:66".parse().unwrap(),
            bmc_credentials: Credentials::UsernamePassword {
                username: "admin".to_string(),
                password: "pass".to_string(),
            },
            nvos_credentials: Credentials::UsernamePassword {
                username: "admin".to_string(),
                password: "pass".to_string(),
            },
        }
    }

    /// Create a backend with a real DB pool seeded with test data.
    async fn make_backend(
        pool: &sqlx::PgPool,
    ) -> (
        Arc<MockRmsApi>,
        RmsBackend,
        RackId,
        PowerShelfId,
        PowerShelfId,
        SwitchId,
        SwitchId,
    ) {
        let (rack_id, ps1, ps2, sw1, sw2) = seed_test_data(pool).await;
        let mock = Arc::new(MockRmsApi::new());
        let backend = RmsBackend::new(mock.clone(), Some(mock.clone()), pool.clone());
        (mock, backend, rack_id, ps1, ps2, sw1, sw2)
    }

    fn firmware_update_options() -> FirmwareUpdateOptions {
        FirmwareUpdateOptions {
            access_token: Some("token".to_owned()),
            force_update: true,
        }
    }

    fn component_filters_for(
        request: &rms::ApplyFirmwareObjectFromJsonRequest,
        node_type: rms::NodeType,
    ) -> &[String] {
        &request
            .component_filters
            .get(&(node_type as i32))
            .expect("component filters for node type")
            .components
    }

    #[test]
    fn direct_rms_firmware_object_json_request_defaults_missing_access_token_to_noauth() {
        let request = apply_firmware_object_from_json_request(
            rms::NewNodeInfo::default(),
            &RmsIdentity {
                node_id: "node-1".to_string(),
                rack_id: "rack-1".to_string(),
            },
            r#"{"Id":"fw-json"}"#,
            &FirmwareUpdateOptions {
                access_token: None,
                force_update: false,
            },
            rms::NodeType::Switch,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(request.access_token, RMS_NOAUTH_ACCESS_TOKEN);
    }

    #[test]
    fn direct_rms_switch_system_image_request_defaults_empty_access_token_to_noauth() {
        let request = apply_switch_system_image_from_json_request(
            rms::NewNodeInfo::default(),
            &RmsIdentity {
                node_id: "node-1".to_string(),
                rack_id: "rack-1".to_string(),
            },
            r#"{"Id":"fw-json"}"#,
            &FirmwareUpdateOptions {
                access_token: Some(String::new()),
                force_update: false,
            },
        )
        .unwrap();

        assert_eq!(request.access_token, RMS_NOAUTH_ACCESS_TOKEN);
    }

    // ---- PowerShelfManager tests ----

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &ps2.to_string(),
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = PowerShelfManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_by_device_list_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOn as i32);
        let dev0 = &calls[0].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev0.node_id, ps1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::Powershelf as i32));
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_none());
        let dev1 = &calls[1].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev1.node_id, ps2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_partial_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_fail(
            &ps2.to_string(),
            "rms reported failure",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = PowerShelfManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert!(results[0].success);
        assert!(!results[1].success);
        assert!(results[1].error.is_some());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_transport_error(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_set_power_state_by_device_list(Err(
            librms::RackManagerError::ApiInvocationError(tonic::Status::unavailable(
                "connection refused",
            )),
        ))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = PowerShelfManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert!(results[0].success);
        assert!(!results[1].success);
        assert!(
            results[1]
                .error
                .as_ref()
                .unwrap()
                .contains("connection refused")
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_unknown_mac(pool: sqlx::PgPool) {
        let (mock, backend, _, _, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &ps2.to_string(),
        )))
        .await;

        let eps = vec![make_ps_endpoint(UNKNOWN_MAC), make_ps_endpoint(PS_MAC_2)];
        let results =
            PowerShelfManager::power_control(&backend, &eps, PowerAction::GracefulShutdown)
                .await
                .unwrap();

        assert!(!results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_by_device_list_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOff as i32);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, _ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-aaa",
        )))
        .await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &_ps2.to_string(),
            "job-bbb",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.apply_firmware_object_from_json_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token, "token");
        assert_eq!(calls[0].firmware_type, "prod");
        assert_eq!(calls[0].hardware_type, "any");
        assert!(calls[0].force_update);
        let filters = component_filters_for(&calls[0], rms::NodeType::Powershelf);
        assert_eq!(filters, ["PowerShelfFW"]);
        let dev0 = &calls[0].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev0.node_id, ps1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::Powershelf as i32));
        assert!(dev0.bmc_endpoint.is_some());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&PS_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::FirmwareObject(
                "job-aaa".to_string()
            )])
        );
        assert_eq!(
            jobs.get(&PS_MAC_2.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::FirmwareObject(
                "job-bbb".to_string()
            )])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_multiple_components(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-1",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc, PowerShelfComponent::Psu],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(results[0].success);

        let calls = mock.apply_firmware_object_from_json_calls().await;
        let filters = component_filters_for(&calls[0], rms::NodeType::Powershelf);
        assert_eq!(filters, ["PowerShelfFW"]);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_fail(
            &ps1.to_string(),
            "bad firmware file",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(!results[0].success);
        assert_eq!(results[0].error.as_deref(), Some("bad firmware file"));
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_failure_clears_tracked_job(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-old",
        )))
        .await;
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_fail(
            &ps1.to_string(),
            "bad firmware file",
        )))
        .await;
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert!(!jobs.contains_key(&PS_MAC_1.parse::<MacAddress>().unwrap()));
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_running(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-xyz",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobRunning,
        )))
        .await;

        let statuses = PowerShelfManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::InProgress);
        assert!(statuses[0].error.is_none());

        let calls = mock.get_firmware_job_status_calls().await;
        assert_eq!(calls[0].job_id, "job-xyz");
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_no_job(pool: sqlx::PgPool) {
        let (_mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let statuses = PowerShelfManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::Unknown);
        assert!(
            statuses[0]
                .error
                .as_ref()
                .unwrap()
                .contains("no firmware job")
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_completed(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-done",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobCompleted,
        )))
        .await;

        let statuses = PowerShelfManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();
        assert_eq!(statuses[0].state, FirmwareState::Completed);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_failed(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-fail",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(rms::GetFirmwareJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            job_state: rms::FirmwareJobState::FwJobFailed as i32,
            error_message: "checksum mismatch".into(),
            ..Default::default()
        }))
        .await;

        let statuses = PowerShelfManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();
        assert_eq!(statuses[0].state, FirmwareState::Failed);
        assert_eq!(statuses[0].error.as_deref(), Some("checksum mismatch"));
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_non_success_without_error_has_diagnostic(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-status-error",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[PowerShelfComponent::Pmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(rms::GetFirmwareJobStatusResponse {
            status: rms::ReturnCode::Failure as i32,
            ..Default::default()
        }))
        .await;

        let statuses = PowerShelfManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();
        assert_eq!(statuses[0].state, FirmwareState::Unknown);
        assert!(
            statuses[0]
                .error
                .as_deref()
                .unwrap()
                .contains("job-status-error")
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ps_list_firmware_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, _, _, _) = make_backend(&pool).await;
        mock.enqueue_get_node_firmware_inventory(Ok(MockRmsApi::firmware_inventory_ok(&[
            ("PMC", "1.2.3"),
            ("PSU", "4.5.6"),
        ])))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert_eq!(results[0].versions, vec!["1.2.3", "4.5.6"]);
        assert!(results[0].error.is_none());

        let calls = mock.get_node_firmware_inventory_calls().await;
        assert_eq!(calls[0].node_id, ps1.to_string());
        assert_eq!(calls[0].rack_id, rack_id.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_list_firmware_rms_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_get_node_firmware_inventory(Ok(rms::GetNodeFirmwareInventoryResponse {
            status: rms::ReturnCode::Failure as i32,
            ..Default::default()
        }))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.is_some());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_list_firmware_transport_error(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_get_node_firmware_inventory(Err(
            librms::RackManagerError::ApiInvocationError(tonic::Status::unavailable("down")),
        ))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.as_ref().unwrap().contains("down"));
    }

    #[carbide_macros::sqlx_test]
    async fn ps_list_firmware_unknown_mac(pool: sqlx::PgPool) {
        let (_mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        let eps = vec![make_ps_endpoint(UNKNOWN_MAC)];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.is_some());
    }

    // ---- NvSwitchManager tests ----

    #[carbide_macros::sqlx_test]
    async fn sw_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, _, _, sw1, sw2) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &sw1.to_string(),
        )))
        .await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &sw2.to_string(),
        )))
        .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1), make_sw_endpoint(SW_MAC_2)];
        let results = NvSwitchManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_by_device_list_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOn as i32);
        let dev0 = &calls[0].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::Switch as i32));
        assert!(dev0.bmc_endpoint.is_some());
        let dev1 = &calls[1].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev1.node_id, sw2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn sw_power_control_unknown_mac(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, sw2) = make_backend(&pool).await;
        mock.enqueue_set_power_state_by_device_list(Ok(MockRmsApi::power_by_device_list_ok(
            &sw2.to_string(),
        )))
        .await;

        let eps = vec![make_sw_endpoint(UNKNOWN_MAC), make_sw_endpoint(SW_MAC_2)];
        let results = NvSwitchManager::power_control(&backend, &eps, PowerAction::ForceOff)
            .await
            .unwrap();

        assert!(!results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_by_device_list_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOff as i32);
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_success(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-job-1",
        )))
        .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let results = backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc, NvSwitchComponent::Bios],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(results[0].success);

        let calls = mock.apply_firmware_object_from_json_calls().await;
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token, "token");
        assert!(calls[0].force_update);
        let filters = component_filters_for(&calls[0], rms::NodeType::Switch);
        assert_eq!(filters, ["BMC", "BIOS"]);
        let dev0 = &calls[0].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::Switch as i32));
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_some());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::FirmwareObject(
                "sw-job-1".to_string()
            )])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_failure_clears_tracked_jobs(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        let eps = vec![make_sw_endpoint(SW_MAC_1)];

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-job-old",
        )))
        .await;
        backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_fail(
            &sw1.to_string(),
            "bad firmware file",
        )))
        .await;
        let results = backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(!results[0].success);
        let jobs = backend.firmware_jobs.lock().unwrap();
        assert!(!jobs.contains_key(&SW_MAC_1.parse::<MacAddress>().unwrap()));
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_nvos_uses_switch_system_image_json(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_switch_system_image_from_json(Ok(
            MockRmsApi::switch_system_image_apply_ok(&sw1.to_string(), "nvos-job-1"),
        ))
        .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let results = backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Nvos],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(results[0].success);
        assert!(
            mock.apply_firmware_object_from_json_calls()
                .await
                .is_empty()
        );

        let calls = mock.apply_switch_system_image_from_json_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token, "token");
        assert_eq!(calls[0].software_type, "prod");
        assert_eq!(calls[0].hardware_type, "any");
        assert_eq!(calls[0].rack_id, rack_id.to_string());
        let dev0 = &calls[0].nodes.as_ref().unwrap().devices[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::Switch as i32));
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_some());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::SwitchSystemImage {
                job_id: "nvos-job-1".to_string(),
                rack_id: rack_id.to_string(),
                node_id: sw1.to_string(),
            }])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_mixed_tracks_both_jobs(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-fw-job",
        )))
        .await;
        mock.enqueue_apply_switch_system_image_from_json(Ok(
            MockRmsApi::switch_system_image_apply_ok(&sw1.to_string(), "sw-nvos-job"),
        ))
        .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let results = backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc, NvSwitchComponent::Nvos],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(results[0].success);
        assert_eq!(mock.apply_firmware_object_from_json_calls().await.len(), 1);
        assert_eq!(
            mock.apply_switch_system_image_from_json_calls().await.len(),
            1
        );

        {
            let jobs = backend.firmware_jobs.lock().unwrap();
            assert_eq!(
                jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
                Some(&vec![
                    RmsTrackedFirmwareJob::FirmwareObject("sw-fw-job".to_string()),
                    RmsTrackedFirmwareJob::SwitchSystemImage {
                        job_id: "sw-nvos-job".to_string(),
                        rack_id: rack_id.to_string(),
                        node_id: sw1.to_string(),
                    },
                ])
            );
        }

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobCompleted,
        )))
        .await;
        mock.enqueue_get_switch_system_image_job_status(Ok(
            MockRmsApi::switch_system_image_job_status_ok("running"),
        ))
        .await;

        let statuses = NvSwitchManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::InProgress);
        assert_eq!(
            mock.get_firmware_job_status_calls().await[0].job_id,
            "sw-fw-job"
        );
        let status_calls = mock.get_switch_system_image_job_status_calls().await;
        assert_eq!(status_calls[0].job_id, "sw-nvos-job");
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_mixed_failure_keeps_submitted_job(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-fw-job",
        )))
        .await;
        mock.enqueue_apply_switch_system_image_from_json(Ok(
            MockRmsApi::switch_system_image_apply_fail(&sw1.to_string(), "bad system image"),
        ))
        .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let results = backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc, NvSwitchComponent::Nvos],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        assert!(!results[0].success);

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::FirmwareObject(
                "sw-fw-job".to_string()
            )])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_firmware_status(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-job-2",
        )))
        .await;
        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobCompleted,
        )))
        .await;

        let statuses = NvSwitchManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::Completed);

        let calls = mock.get_firmware_job_status_calls().await;
        assert_eq!(calls[0].job_id, "sw-job-2");
    }

    #[carbide_macros::sqlx_test]
    async fn sw_firmware_object_status_non_success_without_error_has_diagnostic(
        pool: sqlx::PgPool,
    ) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;

        mock.enqueue_apply_firmware_object_from_json(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-job-status-error",
        )))
        .await;
        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        backend
            .queue_firmware_updates(
                &eps,
                r#"{"Id":"fw-json"}"#,
                &[NvSwitchComponent::Bmc],
                &firmware_update_options(),
            )
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(rms::GetFirmwareJobStatusResponse {
            status: rms::ReturnCode::Failure as i32,
            ..Default::default()
        }))
        .await;

        let statuses = NvSwitchManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::Unknown);
        assert!(
            statuses[0]
                .error
                .as_deref()
                .unwrap()
                .contains("sw-job-status-error")
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_firmware_status_no_job(pool: sqlx::PgPool) {
        let (_mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let statuses = NvSwitchManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::Unknown);
        assert!(
            statuses[0]
                .error
                .as_ref()
                .unwrap()
                .contains("no firmware job")
        );
    }

    #[carbide_macros::sqlx_test]
    async fn list_firmware_bundles_empty_rms(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_list_firmware_objects(Ok(rms::ListFirmwareObjectsResponse {
            objects: Vec::new(),
        }))
        .await;

        let bundles = backend.list_firmware_bundles().await.unwrap();

        assert!(bundles.is_empty());
    }
}
