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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use carbide_instrument::red;
use carbide_rack::firmware_object::rms_access_token_or_noauth;
use carbide_rack::rms_node_type::{
    compute_node_type_for_profile, power_shelf_node_type_for_profile, switch_node_type_for_profile,
};
use carbide_secrets::credentials::Credentials;
use carbide_uuid::rack::RackProfileId;
use librms::protos::rack_manager as rms;
use librms::{RackManagerError, RmsApi};
use mac_address::MacAddress;
use model::component_manager::{
    ComputeTrayComponent, ConfigureSwitchCertificateState, FirmwareState, NvSwitchComponent,
    PowerAction, PowerShelfComponent,
};
use model::rack_type::{RackProfile, RackProfileConfig};
use sqlx::PgPool;
use tracing::instrument;

use crate::compute_tray_manager::{
    Backend as ComputeTrayBackend, ComputeTrayEndpoint, ComputeTrayFirmwareUpdateStatus,
    ComputeTrayManager, ComputeTrayResult,
};
use crate::config::ComponentManagerConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    Backend as NvSwitchBackend, ConfigureSwitchCertificateJobStatus, NvSwitchManager,
    SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus, SwitchPowerStateResult,
    SwitchSlotAndTrayResult,
};
use crate::power_shelf_manager::{
    Backend as PowerShelfBackend, PowerShelfComponentResult, PowerShelfEndpoint,
    PowerShelfFirmwareUpdateStatus, PowerShelfFirmwareVersions, PowerShelfManager,
    PowerShelfPowerStateResult,
};
use crate::types::FirmwareUpdateOptions;

/// Common RMS identity needed to address a device in RMS.
#[derive(Clone)]
struct RmsIdentity {
    node_id: String,
    rack_id: String,
    rack_profile_id: Option<RackProfileId>,
}

struct ResolvedRmsNode<'a> {
    identity: &'a RmsIdentity,
    node_type: rms::NodeType,
}

/// Role for MAC-keyed switch and power shelf lookups.
///
/// Compute trays use `ComputeTrayRmsIdentity` and `resolve_compute_node`
/// because component-manager addresses compute endpoints by BMC IP and also
/// needs the BMC MAC address when building RMS requests.
#[derive(Clone, Copy)]
enum SwitchOrPowerShelfRole {
    PowerShelf,
    Switch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RmsTrackedFirmwareJob {
    FirmwareObject(String),
    SwitchSystemImage(String),
}

// The direct RMS path matches the rack-maintenance flow and applies production
// firmware artifacts only.
const RMS_FIRMWARE_OBJECT_FIRMWARE_TYPE: &str = "prod";
const RMS_SWITCH_SYSTEM_IMAGE_SOFTWARE_TYPE: &str = "prod";
const RMS_FIRMWARE_OBJECT_HARDWARE_TYPE: &str = "any";
const RMS_IDENTITY_LOOKUP_ERROR: &str = "could not resolve RMS identity from database";

/// Validates rack profile fields required by RMS component-manager backends.
///
/// RMS requests use concrete node type variants, such as the product family
/// and vendor-specific compute, switch, or power shelf type. NICo resolves
/// those variants from rack profile product-family and vendor data. When an RMS
/// backend is enabled, invalid or incomplete rack profile data would otherwise
/// surface later as per-device power or firmware operation failures, so
/// validate all configured profiles during startup.
pub fn validate_rms_backend_rack_profiles(
    config: &ComponentManagerConfig,
    rack_profiles: &RackProfileConfig,
) -> Result<(), ComponentManagerError> {
    let compute_uses_rms = matches!(config.compute_tray_backend, ComputeTrayBackend::Rms);
    let switch_uses_rms = matches!(config.nv_switch_backend, NvSwitchBackend::Rms);
    let power_shelf_uses_rms = matches!(config.power_shelf_backend, PowerShelfBackend::Rms);

    if !(compute_uses_rms || switch_uses_rms || power_shelf_uses_rms) {
        return Ok(());
    }

    if rack_profiles.rack_profiles.is_empty() {
        return Err(ComponentManagerError::InvalidArgument(
            "rack_profiles must contain at least one profile when component_manager uses an RMS backend"
                .into(),
        ));
    }

    for (profile_id, profile) in &rack_profiles.rack_profiles {
        if compute_uses_rms {
            require_rms_vendor(
                profile_id,
                "rack_capabilities.compute.vendor",
                profile.rack_capabilities.compute.vendor.as_deref(),
                "compute_tray_backend",
            )?;
            compute_node_type_for_profile(profile).map_err(|error| {
                rms_node_type_config_error(profile_id, "compute", error.to_string())
            })?;
        }

        if switch_uses_rms {
            require_rms_vendor(
                profile_id,
                "rack_capabilities.switch.vendor",
                profile.rack_capabilities.switch.vendor.as_deref(),
                "nv_switch_backend",
            )?;
            switch_node_type_for_profile(profile).map_err(|error| {
                rms_node_type_config_error(profile_id, "switch", error.to_string())
            })?;
        }

        if power_shelf_uses_rms {
            require_rms_vendor(
                profile_id,
                "rack_capabilities.power_shelf.vendor",
                profile.rack_capabilities.power_shelf.vendor.as_deref(),
                "power_shelf_backend",
            )?;
            power_shelf_node_type_for_profile(profile).map_err(|error| {
                rms_node_type_config_error(profile_id, "power shelf", error.to_string())
            })?;
        }
    }

    Ok(())
}

fn require_rms_vendor(
    profile_id: &str,
    field: &str,
    vendor: Option<&str>,
    backend_field: &str,
) -> Result<(), ComponentManagerError> {
    if vendor
        .map(str::trim)
        .is_some_and(|vendor| !vendor.is_empty())
    {
        return Ok(());
    }

    Err(ComponentManagerError::InvalidArgument(format!(
        "rack profile {profile_id} {field} is required when {backend_field} is 'rms'"
    )))
}

fn rms_node_type_config_error(
    profile_id: &str,
    role: &str,
    error: String,
) -> ComponentManagerError {
    ComponentManagerError::InvalidArgument(format!(
        "rack profile {profile_id} cannot resolve RMS {role} node type: {error}"
    ))
}

pub struct RmsBackend {
    client: Arc<dyn RmsApi>,
    switch_system_image_client: Option<Arc<dyn RmsSwitchSystemImageStatusApi>>,
    db: PgPool,
    rack_profiles: Arc<RackProfileConfig>,
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
        rack_profiles: Arc<RackProfileConfig>,
    ) -> Self {
        Self {
            client,
            switch_system_image_client,
            db,
            rack_profiles,
            firmware_jobs: Mutex::new(HashMap::new()),
        }
    }

    fn rack_profile<'a>(
        &'a self,
        identity: &RmsIdentity,
    ) -> Result<&'a RackProfile, ComponentManagerError> {
        let Some(rack_profile_id) = &identity.rack_profile_id else {
            return Err(ComponentManagerError::InvalidArgument(format!(
                "rack {} has no rack_profile_id for RMS node type resolution",
                identity.rack_id
            )));
        };

        self.rack_profiles
            .get(rack_profile_id.as_str())
            .ok_or_else(|| {
                ComponentManagerError::InvalidArgument(format!(
                    "rack profile {} is not configured for RMS node type resolution",
                    rack_profile_id
                ))
            })
    }

    fn resolve_switch_or_power_shelf_node<'a>(
        &self,
        identities: &'a HashMap<MacAddress, RmsIdentity>,
        device_mac: MacAddress,
        role: SwitchOrPowerShelfRole,
    ) -> Result<ResolvedRmsNode<'a>, String> {
        let Some(identity) = identities.get(&device_mac) else {
            return Err(RMS_IDENTITY_LOOKUP_ERROR.to_owned());
        };

        let profile = self
            .rack_profile(identity)
            .map_err(|error| error.to_string())?;
        let node_type = match role {
            SwitchOrPowerShelfRole::PowerShelf => power_shelf_node_type_for_profile(profile),
            SwitchOrPowerShelfRole::Switch => switch_node_type_for_profile(profile),
        }
        .map_err(|error| error.to_string())?;

        Ok(ResolvedRmsNode {
            identity,
            node_type,
        })
    }

    fn resolve_compute_node<'a>(
        &self,
        identity: &'a ComputeTrayRmsIdentity,
    ) -> Result<ResolvedRmsNode<'a>, String> {
        let profile = self
            .rack_profile(&identity.identity)
            .map_err(|error| error.to_string())?;
        let node_type =
            compute_node_type_for_profile(profile).map_err(|error| error.to_string())?;

        Ok(ResolvedRmsNode {
            identity: &identity.identity,
            node_type,
        })
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
                rack_profile_id: row.rack_profile_id,
            },
        );
    }
    Ok(map)
}

/// Resolved RMS identity for a compute tray, keyed by BMC IP.
struct ComputeTrayRmsIdentity {
    identity: RmsIdentity,
    bmc_mac: MacAddress,
}

/// Resolve compute tray BMC IP addresses to RMS identities via the api-db layer.
async fn resolve_compute_tray_identities(
    db: &PgPool,
    bmc_ips: &[IpAddr],
) -> Result<HashMap<IpAddr, ComputeTrayRmsIdentity>, ComponentManagerError> {
    let rows = db::machine::find_rms_identities_by_bmc_ips(db, bmc_ips)
        .await
        .map_err(|e| {
            ComponentManagerError::Internal(format!(
                "failed to resolve compute tray RMS identities: {e}"
            ))
        })?;

    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let Some(rack_id) = row.rack_id else {
            tracing::warn!(bmc_ip = %row.bmc_ip, "compute tray has no rack_id, skipping");
            continue;
        };
        map.insert(
            row.bmc_ip,
            ComputeTrayRmsIdentity {
                identity: RmsIdentity {
                    node_id: row.id,
                    rack_id: rack_id.to_string(),
                    rack_profile_id: row.rack_profile_id,
                },
                bmc_mac: row.bmc_mac_address,
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
                rack_profile_id: row.rack_profile_id,
            },
        );
    }
    Ok(map)
}

fn to_rms_power_operation(action: PowerAction) -> i32 {
    match action {
        PowerAction::On => rms::PowerOperation::On as i32,
        PowerAction::GracefulShutdown | PowerAction::ForceOff => rms::PowerOperation::Off as i32,
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            rms::PowerOperation::Reset as i32
        }
    }
}

fn map_rms_firmware_job_state(state: i32) -> FirmwareState {
    match rms::FirmwareJobState::try_from(state) {
        Ok(rms::FirmwareJobState::Queued) => FirmwareState::Queued,
        Ok(rms::FirmwareJobState::Running) => FirmwareState::InProgress,
        Ok(rms::FirmwareJobState::Completed) => FirmwareState::Completed,
        Ok(rms::FirmwareJobState::Failed) => FirmwareState::Failed,
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

/// Default BMC HTTPS port used when populating `rms::Endpoint` for power
/// shelves. Mirrors the value used by `crate::power_shelf_controller::maintenance`.
const POWER_SHELF_BMC_PORT: u32 = 443;

/// Build the `rms::NodeInfo` describing a power shelf for inclusion in a
/// `BatchSetPowerState` request. The caller-supplied variant of the
/// RPC requires the BMC connection details inline rather than relying on
/// RMS's inventory; power shelves do not expose a host endpoint.
fn build_power_shelf_node_info(
    ep: &PowerShelfEndpoint,
    identity: &RmsIdentity,
    node_type: rms::NodeType,
) -> rms::NodeInfo {
    rms::NodeInfo {
        node_id: identity.node_id.clone(),
        rack_id: identity.rack_id.clone(),
        r#type: Some(node_type as i32),
        bmc_endpoint: Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.pmc_ip.to_string(),
                mac_address: ep.pmc_mac.to_string(),
                host_name: None,
            }),
            port: POWER_SHELF_BMC_PORT,
            credentials: Some(credentials_to_rms(&ep.pmc_credentials)),
            dangerously_accept_invalid_certs: true,
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
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.pmc_mac,
                SwitchOrPowerShelfRole::PowerShelf,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_power_shelf_node_info(ep, resolved.identity, resolved.node_type);
            let request = rms::BatchSetPowerStateRequest {
                nodes: Some(rms::NodeSet {
                    nodes: vec![device],
                }),
                operation,
            };

            match red::instrumented(
                "rms",
                "batch_set_power_state",
                self.client.batch_set_power_state(request),
            )
            .await
            {
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
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.pmc_mac,
                SwitchOrPowerShelfRole::PowerShelf,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_power_shelf_node_info(ep, resolved.identity, resolved.node_type);
            let request = match apply_firmware_object_request(
                device,
                resolved.identity,
                target_version,
                options,
                resolved.node_type,
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

            match red::instrumented(
                "rms",
                "apply_firmware_object",
                self.client.apply_firmware_object(request),
            )
            .await
            {
                Ok(response) => {
                    let (success, error, job_id) = summarize_firmware_object_apply_response(
                        response,
                        &resolved.identity.node_id,
                    );

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
                            RmsTrackedFirmwareJob::SwitchSystemImage(_) => None,
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
            };

            match red::instrumented(
                "rms",
                "get_firmware_job_status",
                self.client.get_firmware_job_status(request),
            )
            .await
            {
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
                    error: Some(RMS_IDENTITY_LOOKUP_ERROR.into()),
                });
                continue;
            };

            let request = rms::GetNodeFirmwareInventoryRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
            };

            match red::instrumented(
                "rms",
                "get_node_firmware_inventory",
                self.client.get_node_firmware_inventory(request),
            )
            .await
            {
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
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.pmc_mac,
                SwitchOrPowerShelfRole::PowerShelf,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(PowerShelfPowerStateResult {
                        pmc_mac: ep.pmc_mac,
                        power_state: None,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_power_shelf_node_info(ep, resolved.identity, resolved.node_type);
            let observed = query_rms_power_state(
                self.client.as_ref(),
                device,
                &resolved.identity.node_id,
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
    let response = red::instrumented(
        "rms",
        "list_firmware_objects",
        client.list_firmware_objects(rms::ListFirmwareObjectsRequest {
            only_available: false,
            hardware_type: String::new(),
        }),
    )
    .await
    .map_err(|e| {
        ComponentManagerError::Internal(format!("failed to list firmware objects from RMS: {e}"))
    })?;

    Ok(response.objects.into_iter().map(|fw| fw.id).collect())
}

/// Default BMC HTTPS port used when populating `rms::Endpoint` for
/// switches. Mirrors the value used by `crate::rack::firmware_update`.
const SWITCH_BMC_PORT: u32 = 443;

/// Default BMC HTTPS port used when populating `rms::Endpoint` for compute
/// trays.
const COMPUTE_TRAY_BMC_PORT: u32 = 443;

fn credentials_to_rms(creds: &Credentials) -> rms::Credentials {
    let Credentials::UsernamePassword { username, password } = creds;
    rms::Credentials {
        auth: Some(rms::credentials::Auth::UserPass(rms::UsernamePassword {
            username: username.clone(),
            password: password.clone(),
        })),
    }
}

/// Build the `rms::NodeInfo` describing a switch for inclusion in a
/// `BatchSetPowerState` request. The caller-supplied variant of the
/// RPC requires the BMC connection details inline rather than relying on
/// RMS's inventory; the NVOS host endpoint is included for completeness.
fn build_switch_node_info(
    ep: &SwitchEndpoint,
    identity: &RmsIdentity,
    node_type: rms::NodeType,
    nvos_host_name: Option<String>,
) -> rms::NodeInfo {
    rms::NodeInfo {
        node_id: identity.node_id.clone(),
        rack_id: identity.rack_id.clone(),
        r#type: Some(node_type as i32),
        bmc_endpoint: Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.bmc_ip.to_string(),
                mac_address: ep.bmc_mac.to_string(),
                host_name: None,
            }),
            port: SWITCH_BMC_PORT,
            credentials: Some(credentials_to_rms(&ep.bmc_credentials)),
            dangerously_accept_invalid_certs: true,
        }),
        host_endpoint: Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.nvos_ip.to_string(),
                mac_address: ep.nvos_mac.to_string(),
                host_name: nvos_host_name,
            }),
            port: 0,
            credentials: Some(credentials_to_rms(&ep.nvos_credentials)),
            dangerously_accept_invalid_certs: true,
        }),
    }
}

async fn resolve_switch_machine_interface_hostnames(
    db: &PgPool,
    endpoints: &[SwitchEndpoint],
) -> Result<HashMap<MacAddress, String>, ComponentManagerError> {
    let mut hostnames = HashMap::new();
    let mut macs_to_lookup = Vec::new();

    for ep in endpoints {
        if let Some(name) = ep.nvos_host_name.as_ref().filter(|name| !name.is_empty()) {
            hostnames.insert(ep.nvos_mac, name.clone());
        } else {
            macs_to_lookup.push(ep.nvos_mac);
        }
    }

    macs_to_lookup.sort_unstable();
    macs_to_lookup.dedup();

    if !macs_to_lookup.is_empty() {
        let from_db = db::machine_interface::find_hostnames_by_mac_addresses(db, &macs_to_lookup)
            .await
            .map_err(|e| {
                ComponentManagerError::Internal(format!(
                    "failed to resolve switch machine interface hostnames: {e}"
                ))
            })?;
        hostnames.extend(from_db);
    }

    Ok(hostnames)
}

/// Summarize a `NodeBatchResponse` into a `(success, error)` pair for a
/// single-node `BatchSetPowerState` call. Prefers per-node error
/// messages, then the batch-level message, and finally a generic fallback.
fn summarize_power_batch(batch: rms::NodeBatchResponse) -> (bool, Option<String>) {
    let stats = batch.stats.unwrap_or_default();
    let success = batch.status == rms::ReturnCode::Success as i32 && stats.failed_nodes == 0;

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
    device: rms::NodeInfo,
    node_id: &str,
    device_mac: MacAddress,
    device_kind: &str,
) -> RmsObservedPowerState {
    let request = rms::BatchGetPowerStateRequest {
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
        }),
    };

    match red::instrumented(
        "rms",
        "batch_get_power_state",
        client.batch_get_power_state(request),
    )
    .await
    {
        Ok(response) => {
            let batch = response.response.clone().unwrap_or_default();
            let stats = batch.stats.unwrap_or_default();

            if batch.status != rms::ReturnCode::Success as i32 || stats.failed_nodes != 0 {
                let summary = if batch.message.is_empty() {
                    format!(
                        "batch status {}, failed_nodes {}",
                        batch.status, stats.failed_nodes
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

fn apply_firmware_object_request(
    device: rms::NodeInfo,
    identity: &RmsIdentity,
    config_json: &str,
    options: &FirmwareUpdateOptions,
    node_type: rms::NodeType,
    components: Vec<String>,
) -> Result<rms::ApplyFirmwareObjectRequest, ComponentManagerError> {
    let access_token = Some(rms_access_token_or_noauth(options.access_token.as_deref()));

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

    Ok(rms::ApplyFirmwareObjectRequest {
        rack_id: identity.rack_id.clone(),
        config_json: config_json.to_owned(),
        access_token,
        firmware_type: RMS_FIRMWARE_OBJECT_FIRMWARE_TYPE.to_owned(),
        hardware_type: RMS_FIRMWARE_OBJECT_HARDWARE_TYPE.to_owned(),
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
        }),
        force_update: options.force_update,
        component_filters,
    })
}

fn apply_switch_system_image_request(
    device: rms::NodeInfo,
    identity: &RmsIdentity,
    config_json: &str,
    options: &FirmwareUpdateOptions,
) -> Result<rms::ApplySwitchSystemImageRequest, ComponentManagerError> {
    let access_token = Some(rms_access_token_or_noauth(options.access_token.as_deref()));

    if config_json.trim().is_empty() {
        return Err(ComponentManagerError::InvalidArgument(
            "target_version must contain firmware-object JSON for direct RMS updates".into(),
        ));
    }

    Ok(rms::ApplySwitchSystemImageRequest {
        rack_id: identity.rack_id.clone(),
        config_json: config_json.to_owned(),
        access_token,
        software_type: RMS_SWITCH_SYSTEM_IMAGE_SOFTWARE_TYPE.to_owned(),
        hardware_type: RMS_FIRMWARE_OBJECT_HARDWARE_TYPE.to_owned(),
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
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

fn compute_tray_firmware_object_component_filters(
    components: &[ComputeTrayComponent],
) -> Vec<String> {
    if components.is_empty() {
        Vec::new()
    } else {
        components
            .iter()
            .map(|component| component.to_string())
            .collect()
    }
}

/// Build the `rms::NodeInfo` describing a compute tray for inclusion in an
/// RMS batch request. Compute trays expose only a BMC endpoint.
fn build_compute_tray_node_info(
    ep: &ComputeTrayEndpoint,
    identity: &RmsIdentity,
    bmc_mac: MacAddress,
    node_type: rms::NodeType,
) -> rms::NodeInfo {
    rms::NodeInfo {
        node_id: identity.node_id.clone(),
        rack_id: identity.rack_id.clone(),
        r#type: Some(node_type as i32),
        bmc_endpoint: Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: ep.bmc_ip.to_string(),
                mac_address: bmc_mac.to_string(),
                host_name: None,
            }),
            port: COMPUTE_TRAY_BMC_PORT,
            credentials: Some(credentials_to_rms(&ep.bmc_credentials)),
            dangerously_accept_invalid_certs: true,
        }),
        host_endpoint: None,
    }
}

fn summarize_firmware_object_apply_response(
    response: rms::ApplyFirmwareObjectResponse,
    node_id: &str,
) -> (bool, Option<String>, Option<String>) {
    let node_job_id = response
        .jobs
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
        .jobs
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
    let stats = batch.stats.unwrap_or_default();
    let success = batch.status == rms::ReturnCode::Success as i32
        && stats.failed_nodes == 0
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
            };

            match red::instrumented(
                "rms",
                "get_firmware_job_status",
                client.get_firmware_job_status(request),
            )
            .await
            {
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
        RmsTrackedFirmwareJob::SwitchSystemImage(job_id) => {
            let Some(client) = switch_system_image_client else {
                return (
                    FirmwareState::Unknown,
                    Some("RMS switch system-image status client is not configured".to_owned()),
                );
            };
            let request = rms::GetSwitchSystemImageJobStatusRequest {
                job_id: job_id.clone(),
            };

            match red::instrumented(
                "rms",
                "get_switch_system_image_job_status",
                client.get_switch_system_image_job_status(request),
            )
            .await
            {
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
        let hostnames = resolve_switch_machine_interface_hostnames(&self.db, endpoints).await?;

        for ep in endpoints {
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.bmc_mac,
                SwitchOrPowerShelfRole::Switch,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_switch_node_info(
                ep,
                resolved.identity,
                resolved.node_type,
                hostnames.get(&ep.nvos_mac).cloned(),
            );
            let request = rms::BatchSetPowerStateRequest {
                nodes: Some(rms::NodeSet {
                    nodes: vec![device],
                }),
                operation,
            };

            match red::instrumented(
                "rms",
                "batch_set_power_state",
                self.client.batch_set_power_state(request),
            )
            .await
            {
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
        let hostnames = resolve_switch_machine_interface_hostnames(&self.db, endpoints).await?;

        for ep in endpoints {
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.bmc_mac,
                SwitchOrPowerShelfRole::Switch,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let nvos_host_name = hostnames.get(&ep.nvos_mac).cloned();
            let mut success = true;
            let mut errors = Vec::new();
            let mut tracked_jobs = Vec::new();

            if include_firmware_object {
                let device = build_switch_node_info(
                    ep,
                    resolved.identity,
                    resolved.node_type,
                    nvos_host_name.clone(),
                );
                match apply_firmware_object_request(
                    device,
                    resolved.identity,
                    bundle_version,
                    options,
                    resolved.node_type,
                    component_filters.clone(),
                ) {
                    Ok(request) => match red::instrumented(
                        "rms",
                        "apply_firmware_object",
                        self.client.apply_firmware_object(request),
                    )
                    .await
                    {
                        Ok(response) => {
                            let (operation_success, error, job_id) =
                                summarize_firmware_object_apply_response(
                                    response,
                                    &resolved.identity.node_id,
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
                let device = build_switch_node_info(
                    ep,
                    resolved.identity,
                    resolved.node_type,
                    nvos_host_name,
                );
                match apply_switch_system_image_request(
                    device,
                    resolved.identity,
                    bundle_version,
                    options,
                ) {
                    Ok(request) => match red::instrumented(
                        "rms",
                        "apply_switch_system_image",
                        self.client.apply_switch_system_image(request),
                    )
                    .await
                    {
                        Ok(response) => {
                            let (operation_success, error, job_id) =
                                summarize_switch_system_image_apply_response(
                                    response,
                                    &resolved.identity.node_id,
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
                                        .push(RmsTrackedFirmwareJob::SwitchSystemImage(job_id));
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
                    },
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
        let hostnames = resolve_switch_machine_interface_hostnames(&self.db, endpoints).await?;

        for ep in endpoints {
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.bmc_mac,
                SwitchOrPowerShelfRole::Switch,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(SwitchPowerStateResult {
                        bmc_mac: ep.bmc_mac,
                        power_state: None,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_switch_node_info(
                ep,
                resolved.identity,
                resolved.node_type,
                hostnames.get(&ep.nvos_mac).cloned(),
            );
            let observed = query_rms_power_state(
                self.client.as_ref(),
                device,
                &resolved.identity.node_id,
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
        let hostnames = resolve_switch_machine_interface_hostnames(&self.db, endpoints).await?;

        for ep in endpoints {
            let resolved = match self.resolve_switch_or_power_shelf_node(
                &ids,
                ep.bmc_mac,
                SwitchOrPowerShelfRole::Switch,
            ) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(SwitchSlotAndTrayResult {
                        bmc_mac: ep.bmc_mac,
                        slot_number: None,
                        tray_index: None,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_switch_node_info(
                ep,
                resolved.identity,
                resolved.node_type,
                hostnames.get(&ep.nvos_mac).cloned(),
            );
            let request = rms::BatchGetNodeDeviceInfoRequest {
                nodes: Some(rms::NodeSet {
                    nodes: vec![device],
                }),
            };

            match red::instrumented(
                "rms",
                "batch_get_node_device_info",
                self.client.batch_get_node_device_info(request),
            )
            .await
            {
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

                    let Some(node_device_details) = info.node_device_details.first() else {
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
                        slot_number: node_device_details
                            .slot_number
                            .and_then(|value| i32::try_from(value).ok()),
                        tray_index: node_device_details
                            .tray_index
                            .and_then(|value| i32::try_from(value).ok()),
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

    #[instrument(skip(self, domain_name), fields(backend = "rms"))]
    async fn configure_switch_certificate(
        &self,
        endpoint: &SwitchEndpoint,
        domain_name: Option<&str>,
        services: Option<&[i32]>,
    ) -> Result<String, ComponentManagerError> {
        let ids =
            resolve_switch_identities(&self.db, std::slice::from_ref(&endpoint.bmc_mac)).await?;

        let resolved = match self.resolve_switch_or_power_shelf_node(
            &ids,
            endpoint.bmc_mac,
            SwitchOrPowerShelfRole::Switch,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                return Err(ComponentManagerError::Internal(error));
            }
        };
        let Some(identity) = ids.get(&endpoint.bmc_mac) else {
            return Err(ComponentManagerError::Internal(
                "could not resolve RMS identity from database".into(),
            ));
        };

        let hostnames =
            resolve_switch_machine_interface_hostnames(&self.db, std::slice::from_ref(endpoint))
                .await?;

        let device = build_switch_node_info(
            endpoint,
            identity,
            resolved.node_type,
            hostnames.get(&endpoint.nvos_mac).cloned(),
        );
        rms_configure_switch_certificate(self.client.as_ref(), device, domain_name, services).await
    }

    #[instrument(skip(self), fields(backend = "rms", job_id))]
    async fn get_configure_switch_certificate_job_status(
        &self,
        job_id: &str,
    ) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError> {
        rms_get_configure_switch_certificate_job_status(self.client.as_ref(), job_id).await
    }
}

fn map_rms_configure_switch_certificate_job_state(state: &str) -> ConfigureSwitchCertificateState {
    match state.to_ascii_lowercase().as_str() {
        "queued" | "pending" => ConfigureSwitchCertificateState::Started,
        "running" | "in_progress" | "active" => ConfigureSwitchCertificateState::InProgress,
        "completed" | "success" | "done" => ConfigureSwitchCertificateState::Completed,
        "failed" | "error" => ConfigureSwitchCertificateState::Failed,
        _ => ConfigureSwitchCertificateState::InProgress,
    }
}

fn summarize_configure_switch_certificate_response(
    response: rms::ConfigureSwitchCertificateResponse,
    node_id: &str,
) -> (bool, Option<String>, Option<String>) {
    let node_job_id = response
        .jobs
        .iter()
        .find(|j| j.node_id == node_id && !j.job_id.is_empty())
        .map(|j| j.job_id.clone());

    summarize_firmware_batch(
        response.response,
        node_job_id,
        node_id,
        "RMS switch certificate configuration failed",
    )
}

async fn rms_configure_switch_certificate(
    client: &dyn RmsApi,
    device: rms::NodeInfo,
    domain_name: Option<&str>,
    services: Option<&[i32]>,
) -> Result<String, ComponentManagerError> {
    let node_id = device.node_id.clone();
    let request = rms::ConfigureSwitchCertificateRequest {
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
        }),
        services: services.map(<[i32]>::to_vec).unwrap_or_default(),
        test_hello: true,
        domain: domain_name.map(str::to_owned),
    };

    let response = red::instrumented(
        "rms",
        "configure_switch_certificate",
        client.configure_switch_certificate(request),
    )
    .await
    .map_err(|e| {
        ComponentManagerError::Internal(format!(
            "failed to start RMS switch certificate configuration: {e}"
        ))
    })?;

    let (success, error, job_id) =
        summarize_configure_switch_certificate_response(response, &node_id);

    if success {
        job_id.ok_or_else(|| {
            ComponentManagerError::Internal(
                "RMS switch certificate configuration succeeded but returned no job id".into(),
            )
        })
    } else {
        Err(ComponentManagerError::Internal(error.unwrap_or_else(
            || "RMS switch certificate configuration failed".to_owned(),
        )))
    }
}

async fn rms_get_configure_switch_certificate_job_status(
    client: &dyn RmsApi,
    job_id: &str,
) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError> {
    let request = rms::GetConfigureSwitchCertificateJobStatusRequest {
        job_id: job_id.to_owned(),
    };

    let response = red::instrumented(
        "rms",
        "get_configure_switch_certificate_job_status",
        client.get_configure_switch_certificate_job_status(request),
    )
    .await
    .map_err(|e| {
        ComponentManagerError::Internal(format!(
            "failed to get RMS switch certificate job status: {e}"
        ))
    })?;

    if response.status != rms::ReturnCode::Success as i32 {
        let error = if response.error_message.is_empty() {
            if response.message.is_empty() {
                format!("RMS could not report status for switch certificate job {job_id}")
            } else {
                response.message
            }
        } else {
            response.error_message
        };
        return Ok(ConfigureSwitchCertificateJobStatus {
            state: ConfigureSwitchCertificateState::Failed,
            error: Some(error),
        });
    }

    let state = map_rms_configure_switch_certificate_job_state(&response.state);
    let error = if matches!(state, ConfigureSwitchCertificateState::Failed) {
        Some(
            (!response.error_message.is_empty())
                .then_some(response.error_message)
                .or((!response.message.is_empty()).then_some(response.message))
                .unwrap_or_else(|| "switch certificate configuration failed".to_owned()),
        )
    } else {
        None
    };

    Ok(ConfigureSwitchCertificateJobStatus { state, error })
}

#[async_trait::async_trait]
impl ComputeTrayManager for RmsBackend {
    fn name(&self) -> &str {
        "rms"
    }

    fn backend(&self) -> ComputeTrayBackend {
        ComputeTrayBackend::Rms
    }

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn power_control(
        &self,
        endpoints: &[ComputeTrayEndpoint],
        action: PowerAction,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError> {
        let bmc_ips: Vec<IpAddr> = endpoints.iter().map(|ep| ep.bmc_ip).collect();
        let ids = resolve_compute_tray_identities(&self.db, &bmc_ips).await?;
        let operation = to_rms_power_operation(action);
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_ip) else {
                results.push(ComputeTrayResult {
                    bmc_ip: ep.bmc_ip,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let resolved = match self.resolve_compute_node(identity) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_compute_tray_node_info(
                ep,
                resolved.identity,
                identity.bmc_mac,
                resolved.node_type,
            );
            let request = rms::BatchSetPowerStateRequest {
                nodes: Some(rms::NodeSet {
                    nodes: vec![device],
                }),
                operation,
            };

            match red::instrumented(
                "rms",
                "batch_set_power_state",
                self.client.batch_set_power_state(request),
            )
            .await
            {
                Ok(response) => {
                    let (success, error) =
                        summarize_power_batch(response.response.unwrap_or_default());
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
                        success,
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_ip = %ep.bmc_ip,
                        error = %e,
                        "RMS power control failed for compute tray"
                    );
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
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
        endpoints: &[ComputeTrayEndpoint],
        target_version: &str,
        components: &[ComputeTrayComponent],
        options: &FirmwareUpdateOptions,
    ) -> Result<Vec<ComputeTrayResult>, ComponentManagerError> {
        let bmc_ips: Vec<IpAddr> = endpoints.iter().map(|ep| ep.bmc_ip).collect();
        let ids = resolve_compute_tray_identities(&self.db, &bmc_ips).await?;
        let component_filters = compute_tray_firmware_object_component_filters(components);
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in endpoints {
            let Some(identity) = ids.get(&ep.bmc_ip) else {
                results.push(ComputeTrayResult {
                    bmc_ip: ep.bmc_ip,
                    success: false,
                    error: Some("could not resolve RMS identity from database".into()),
                });
                continue;
            };

            let resolved = match self.resolve_compute_node(identity) {
                Ok(resolved) => resolved,
                Err(error) => {
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
                        success: false,
                        error: Some(error),
                    });
                    continue;
                }
            };

            let device = build_compute_tray_node_info(
                ep,
                resolved.identity,
                identity.bmc_mac,
                resolved.node_type,
            );
            let request = match apply_firmware_object_request(
                device,
                resolved.identity,
                target_version,
                options,
                resolved.node_type,
                component_filters.clone(),
            ) {
                Ok(request) => request,
                Err(e) => {
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
                        success: false,
                        error: Some(e.to_string()),
                    });
                    continue;
                }
            };

            match red::instrumented(
                "rms",
                "apply_firmware_object",
                self.client.apply_firmware_object(request),
            )
            .await
            {
                Ok(response) => {
                    let (success, error, job_id) = summarize_firmware_object_apply_response(
                        response,
                        &resolved.identity.node_id,
                    );

                    if success {
                        if let Some(job_id) = job_id {
                            self.firmware_jobs.lock().unwrap().insert(
                                identity.bmc_mac,
                                vec![RmsTrackedFirmwareJob::FirmwareObject(job_id)],
                            );
                        } else {
                            self.firmware_jobs.lock().unwrap().remove(&identity.bmc_mac);
                        }
                    } else {
                        self.firmware_jobs.lock().unwrap().remove(&identity.bmc_mac);
                    }

                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
                        success,
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_ip = %ep.bmc_ip,
                        error = %e,
                        "RMS firmware update failed for compute tray"
                    );
                    results.push(ComputeTrayResult {
                        bmc_ip: ep.bmc_ip,
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
        endpoints: &[ComputeTrayEndpoint],
    ) -> Result<Vec<ComputeTrayFirmwareUpdateStatus>, ComponentManagerError> {
        let bmc_ips: Vec<IpAddr> = endpoints.iter().map(|ep| ep.bmc_ip).collect();
        let ids = resolve_compute_tray_identities(&self.db, &bmc_ips).await?;

        let endpoint_jobs: Vec<(IpAddr, Option<String>)> = {
            let jobs = self.firmware_jobs.lock().unwrap();
            endpoints
                .iter()
                .map(|ep| {
                    let job_id = ids.get(&ep.bmc_ip).and_then(|identity| {
                        jobs.get(&identity.bmc_mac).and_then(|jobs| {
                            jobs.iter().find_map(|job| match job {
                                RmsTrackedFirmwareJob::FirmwareObject(job_id) => {
                                    Some(job_id.clone())
                                }
                                RmsTrackedFirmwareJob::SwitchSystemImage(_) => None,
                            })
                        })
                    });
                    (ep.bmc_ip, job_id)
                })
                .collect()
        };

        let mut statuses = Vec::with_capacity(endpoints.len());

        for (bmc_ip, job_id) in &endpoint_jobs {
            let Some(job_id) = job_id else {
                statuses.push(ComputeTrayFirmwareUpdateStatus {
                    bmc_ip: *bmc_ip,
                    state: FirmwareState::Unknown,
                    target_version: String::new(),
                    error: Some("no firmware job tracked for this compute tray".into()),
                });
                continue;
            };

            let request = rms::GetFirmwareJobStatusRequest {
                job_id: job_id.clone(),
            };

            match red::instrumented(
                "rms",
                "get_firmware_job_status",
                self.client.get_firmware_job_status(request),
            )
            .await
            {
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
                    statuses.push(ComputeTrayFirmwareUpdateStatus {
                        bmc_ip: *bmc_ip,
                        state,
                        target_version: String::new(),
                        error,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_ip = %bmc_ip,
                        job_id = %job_id,
                        error = %e,
                        "RMS firmware job status query failed"
                    );
                    statuses.push(ComputeTrayFirmwareUpdateStatus {
                        bmc_ip: *bmc_ip,
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
    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        list_firmware_object_ids(self.client.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use api_test_helper::mock_rms::MockRmsApi;
    use carbide_test_support::value_scenarios;
    use carbide_uuid::machine::MachineId;
    use carbide_uuid::power_shelf::PowerShelfId;
    use carbide_uuid::rack::RackId;
    use carbide_uuid::switch::SwitchId;
    use model::rack_type::{
        RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
        RackHardwareTopology, RackProductFamily, RackProfile, RackProfileConfig,
    };

    use super::*;
    use crate::compute_tray_manager::{ComputeTrayManager, ComputeTrayVendor};
    use crate::config::SwitchMtlsService;
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
        CT_IP_1, CT_IP_2, CT_MAC_1, CT_MAC_2, PS_MAC_1, PS_MAC_2, SW_MAC_1, SW_MAC_2,
        TEST_RACK_PROFILE_ID, UNKNOWN_MAC, seed_machine, seed_test_data,
    };

    // ---- Mapping unit tests ----

    #[test]
    fn power_action_maps_to_rms_operation() {
        value_scenarios!(to_rms_power_operation:
            "power on" {
                PowerAction::On => rms::PowerOperation::On as i32,
            }

            "power off" {
                PowerAction::GracefulShutdown => rms::PowerOperation::Off as i32,
                PowerAction::ForceOff => rms::PowerOperation::Off as i32,
            }

            "reset" {
                PowerAction::GracefulRestart => rms::PowerOperation::Reset as i32,
                PowerAction::ForceRestart => rms::PowerOperation::Reset as i32,
                PowerAction::AcPowercycle => rms::PowerOperation::Reset as i32,
            }
        );
    }

    #[test]
    fn firmware_job_state_maps_each_variant() {
        value_scenarios!(run = |state: rms::FirmwareJobState| map_rms_firmware_job_state(state as i32);
            "states" {
                rms::FirmwareJobState::Queued => FirmwareState::Queued,
                rms::FirmwareJobState::Running => FirmwareState::InProgress,
                rms::FirmwareJobState::Completed => FirmwareState::Completed,
                rms::FirmwareJobState::Failed => FirmwareState::Failed,
            }
        );
    }

    #[test]
    fn firmware_job_state_unknown_for_unrecognized_value() {
        value_scenarios!(map_rms_firmware_job_state:
            "unrecognized" {
                9999 => FirmwareState::Unknown,
            }
        );
    }

    #[test]
    fn switch_system_image_job_state_maps_cancelled_and_verifying() {
        value_scenarios!(map_rms_switch_system_image_job_state:
            "cancelled" {
                "cancelled" => FirmwareState::Cancelled,
            }

            "verifying" {
                "verifying" => FirmwareState::Verifying,
            }
        );
    }

    #[test]
    fn configure_switch_certificate_job_state_maps_rms_states() {
        assert_eq!(
            map_rms_configure_switch_certificate_job_state("queued"),
            ConfigureSwitchCertificateState::Started,
        );
        assert_eq!(
            map_rms_configure_switch_certificate_job_state("running"),
            ConfigureSwitchCertificateState::InProgress,
        );
        assert_eq!(
            map_rms_configure_switch_certificate_job_state("completed"),
            ConfigureSwitchCertificateState::Completed,
        );
        assert_eq!(
            map_rms_configure_switch_certificate_job_state("failed"),
            ConfigureSwitchCertificateState::Failed,
        );
        assert_eq!(
            map_rms_configure_switch_certificate_job_state("unknown"),
            ConfigureSwitchCertificateState::InProgress,
        );
    }

    #[test]
    fn aggregate_firmware_job_states_prioritizes_active_over_unknown() {
        value_scenarios!(run = |states| aggregate_firmware_job_states(states);
            "active wins over unknown" {
                &[
                    FirmwareState::Completed,
                    FirmwareState::Unknown,
                    FirmwareState::InProgress,
                ] => FirmwareState::InProgress,
                &[
                    FirmwareState::Completed,
                    FirmwareState::Queued,
                    FirmwareState::Unknown,
                ] => FirmwareState::Queued,
            }
        );
    }

    #[test]
    fn aggregate_firmware_job_states_terminal_failures_win() {
        value_scenarios!(run = |states| aggregate_firmware_job_states(states);
            "terminal failures win" {
                &[
                    FirmwareState::Failed,
                    FirmwareState::InProgress,
                    FirmwareState::Unknown,
                ] => FirmwareState::Failed,
                &[
                    FirmwareState::Cancelled,
                    FirmwareState::InProgress,
                    FirmwareState::Unknown,
                ] => FirmwareState::Cancelled,
            }
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
    fn compute_tray_component_filters_map_to_rms_names() {
        assert_eq!(
            compute_tray_firmware_object_component_filters(&[
                ComputeTrayComponent::Bmc,
                ComputeTrayComponent::Bios,
            ]),
            vec!["BMC".to_owned(), "BIOS".to_owned()]
        );
        assert!(compute_tray_firmware_object_component_filters(&[]).is_empty());
    }

    #[test]
    fn firmware_update_missing_batch_response_is_failure() {
        let response = rms::ApplyFirmwareObjectResponse {
            response: None,
            object_id: "fw-json".to_owned(),
            jobs: vec![rms::NodeFirmwareJobInfo {
                node_id: "node-1".to_owned(),
                job_id: "job-1".to_owned(),
            }],
        };

        let (success, error, job_id) = summarize_firmware_object_apply_response(response, "node-1");

        assert!(!success);
        assert_eq!(error.as_deref(), Some("RMS firmware update failed"));
        assert_eq!(job_id.as_deref(), Some("job-1"));
    }

    #[tokio::test]
    async fn rms_calls_record_the_external_call_histogram_by_outcome() {
        use carbide_instrument::testing::MetricsCapture;

        let mock = MockRmsApi::new();
        mock.enqueue_batch_get_power_state(Ok(rms::BatchGetPowerStateResponse::default()))
            .await;
        mock.enqueue_batch_get_power_state(Err(RackManagerError::ApiInvocationError(
            tonic::Status::unavailable("down"),
        )))
        .await;

        let device_mac: MacAddress = PS_MAC_1.parse().unwrap();
        let metrics = MetricsCapture::start();
        let mut observed = Vec::new();
        for _ in 0..2 {
            observed.push(
                query_rms_power_state(
                    &mock,
                    rms::NodeInfo::default(),
                    "node-1",
                    device_mac,
                    "power shelf",
                )
                .await,
            );
        }
        assert!(
            observed[1].error.is_some(),
            "transport failure surfaces as an error"
        );

        for outcome in ["ok", "error"] {
            assert_eq!(
                metrics.histogram_count_delta(
                    "carbide_external_call_duration_milliseconds",
                    &[
                        ("backend", "rms"),
                        ("operation", "batch_get_power_state"),
                        ("outcome", outcome),
                    ],
                ),
                1,
                "{outcome}"
            );
        }
    }

    // ---- Test helpers ----

    fn make_ps_endpoint(mac: &str) -> PowerShelfEndpoint {
        use carbide_secrets::credentials::Credentials;
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
        use carbide_secrets::credentials::Credentials;
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
            nvos_host_name: None,
        }
    }

    fn rack_profile_config() -> RackProfileConfig {
        RackProfileConfig {
            rack_profiles: [(
                TEST_RACK_PROFILE_ID.to_string(),
                RackProfile {
                    product_family: Some(RackProductFamily::Gb200),
                    rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
                    rack_capabilities: RackCapabilitiesSet {
                        compute: RackCapabilityCompute {
                            vendor: Some("NVIDIA".to_string()),
                            ..Default::default()
                        },
                        switch: RackCapabilitySwitch {
                            vendor: Some("NVIDIA".to_string()),
                            ..Default::default()
                        },
                        power_shelf: RackCapabilityPowerShelf {
                            vendor: Some("LiteOn".to_string()),
                            ..Default::default()
                        },
                    },
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
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
        let backend = RmsBackend::new(
            mock.clone(),
            Some(mock.clone()),
            pool.clone(),
            Arc::new(rack_profile_config()),
        );
        (mock, backend, rack_id, ps1, ps2, sw1, sw2)
    }

    async fn make_compute_tray_backend(
        pool: &sqlx::PgPool,
    ) -> (Arc<MockRmsApi>, RmsBackend, RackId, MachineId, MachineId) {
        let mut txn = pool.begin().await.unwrap();
        let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
        let rack_profile_id = RackProfileId::new(TEST_RACK_PROFILE_ID);
        db::rack::create(
            &mut txn,
            &rack_id,
            Some(&rack_profile_id),
            &model::rack::RackConfig::default(),
            None,
        )
        .await
        .expect("failed to create rack");
        let ct1 = seed_machine(&mut txn, CT_MAC_1, CT_IP_1, "CT-001", &rack_id).await;
        let ct2 = seed_machine(&mut txn, CT_MAC_2, CT_IP_2, "CT-002", &rack_id).await;
        txn.commit().await.unwrap();

        let mock = Arc::new(MockRmsApi::new());
        let backend = RmsBackend::new(
            mock.clone(),
            Some(mock.clone()),
            pool.clone(),
            Arc::new(rack_profile_config()),
        );
        (mock, backend, rack_id, ct1, ct2)
    }

    fn make_ct_endpoint(bmc_ip: &str) -> ComputeTrayEndpoint {
        use carbide_secrets::credentials::Credentials;
        ComputeTrayEndpoint {
            vendor: ComputeTrayVendor::Nvidia,
            bmc_ip: bmc_ip.parse().unwrap(),
            bmc_credentials: Credentials::UsernamePassword {
                username: "admin".into(),
                password: "pass".into(),
            },
        }
    }

    fn firmware_update_options() -> FirmwareUpdateOptions {
        FirmwareUpdateOptions {
            access_token: Some("token".to_owned()),
            force_update: true,
        }
    }

    fn component_filters_for(
        request: &rms::ApplyFirmwareObjectRequest,
        node_type: rms::NodeType,
    ) -> &[String] {
        &request
            .component_filters
            .get(&(node_type as i32))
            .expect("component filters for node type")
            .components
    }

    fn single_batch_set_power_state_node_type(
        calls: &[rms::BatchSetPowerStateRequest],
    ) -> Option<i32> {
        let [call] = calls else {
            return None;
        };
        let nodes = call.nodes.as_ref()?;
        let [node] = nodes.nodes.as_slice() else {
            return None;
        };

        node.r#type
    }

    #[test]
    fn direct_rms_power_shelf_node_info_uses_concrete_node_type() {
        let endpoint = make_ps_endpoint(PS_MAC_1);
        let identity = RmsIdentity {
            node_id: "node-1".to_string(),
            rack_id: "rack-1".to_string(),
            rack_profile_id: None,
        };

        let node =
            build_power_shelf_node_info(&endpoint, &identity, rms::NodeType::PowershelfGb300Delta);

        assert_eq!(
            node.r#type,
            Some(rms::NodeType::PowershelfGb300Delta as i32)
        );
    }

    #[test]
    fn direct_rms_switch_node_info_uses_concrete_node_type() {
        let endpoint = make_sw_endpoint(SW_MAC_1);
        let identity = RmsIdentity {
            node_id: "node-1".to_string(),
            rack_id: "rack-1".to_string(),
            rack_profile_id: None,
        };

        let node =
            build_switch_node_info(&endpoint, &identity, rms::NodeType::SwitchGb300Nvidia, None);

        assert_eq!(node.r#type, Some(rms::NodeType::SwitchGb300Nvidia as i32));
    }

    #[test]
    fn direct_rms_firmware_object_json_request_defaults_missing_access_token_to_noauth() {
        let request = apply_firmware_object_request(
            rms::NodeInfo::default(),
            &RmsIdentity {
                node_id: "node-1".to_string(),
                rack_id: "rack-1".to_string(),
                rack_profile_id: None,
            },
            r#"{"Id":"fw-json"}"#,
            &FirmwareUpdateOptions {
                access_token: None,
                force_update: false,
            },
            rms::NodeType::SwitchGb200Nvidia,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            request.access_token.as_deref(),
            Some(carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN)
        );
    }

    #[carbide_macros::sqlx_test]
    async fn power_shelf_power_control_request_uses_profile_vendor_node_type(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;

        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ps1.to_string(),
        )))
        .await;
        let results = PowerShelfManager::power_control(
            &backend,
            &[make_ps_endpoint(PS_MAC_1)],
            PowerAction::On,
        )
        .await?;

        assert!(results[0].success);

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(
            single_batch_set_power_state_node_type(&calls),
            Some(rms::NodeType::PowershelfGb200Liteon as i32)
        );

        Ok(())
    }

    #[test]
    fn direct_rms_switch_system_image_request_defaults_empty_access_token_to_noauth() {
        let request = apply_switch_system_image_request(
            rms::NodeInfo::default(),
            &RmsIdentity {
                node_id: "node-1".to_string(),
                rack_id: "rack-1".to_string(),
                rack_profile_id: None,
            },
            r#"{"Id":"fw-json"}"#,
            &FirmwareUpdateOptions {
                access_token: Some(String::new()),
                force_update: false,
            },
        )
        .unwrap();

        assert_eq!(
            request.access_token.as_deref(),
            Some(carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN)
        );
    }

    // ---- PowerShelfManager tests ----

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
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

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, rms::PowerOperation::On as i32);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, ps1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(
            dev0.r#type,
            Some(rms::NodeType::PowershelfGb200Liteon as i32)
        );
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_none());
        let dev1 = &calls[1].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev1.node_id, ps2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_partial_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_fail(
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
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ps1.to_string(),
        )))
        .await;
        mock.enqueue_batch_set_power_state(Err(librms::RackManagerError::ApiInvocationError(
            tonic::Status::unavailable("connection refused"),
        )))
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
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
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

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, rms::PowerOperation::Off as i32);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, _ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-aaa",
        )))
        .await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &_ps2.to_string(),
            "job-bbb",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.apply_firmware_object_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token.as_deref(), Some("token"));
        assert_eq!(calls[0].firmware_type, "prod");
        assert_eq!(calls[0].hardware_type, "any");
        assert!(calls[0].force_update);
        let filters = component_filters_for(&calls[0], rms::NodeType::PowershelfGb200Liteon);
        assert_eq!(filters, ["PowerShelfFW"]);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, ps1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(
            dev0.r#type,
            Some(rms::NodeType::PowershelfGb200Liteon as i32)
        );
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
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-1",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc, PowerShelfComponent::Psu],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        assert!(results[0].success);

        let calls = mock.apply_firmware_object_calls().await;
        let filters = component_filters_for(&calls[0], rms::NodeType::PowershelfGb200Liteon);
        assert_eq!(filters, ["PowerShelfFW"]);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, ps1, _, _, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_fail(
            &ps1.to_string(),
            "bad firmware file",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = PowerShelfManager::update_firmware(
            &backend,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-old",
        )))
        .await;
        PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_fail(
            &ps1.to_string(),
            "bad firmware file",
        )))
        .await;
        PowerShelfManager::update_firmware(
            &backend,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-xyz",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::Running,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-done",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::Completed,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-fail",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        PowerShelfManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[PowerShelfComponent::Pmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(rms::GetFirmwareJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            job_state: rms::FirmwareJobState::Failed as i32,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ps1.to_string(),
            "job-status-error",
        )))
        .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        PowerShelfManager::update_firmware(
            &backend,
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
    async fn sw_configure_switch_certificate_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_configure_switch_certificate(Ok(MockRmsApi::configure_switch_certificate_ok(
            &sw1.to_string(),
            "cert-job-1",
        )))
        .await;

        let endpoint = make_sw_endpoint(SW_MAC_1);
        let job_id = NvSwitchManager::configure_switch_certificate(
            &backend,
            &endpoint,
            Some(rack_id.as_ref()),
            Some(&crate::config::switch_mtls_services_as_i32(
                &SwitchMtlsService::default_services(),
            )),
        )
        .await
        .unwrap();

        assert_eq!(job_id, "cert-job-1");

        let calls = mock.configure_switch_certificate_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].domain, Some(rack_id.to_string()));
        assert_eq!(
            calls[0].nodes.as_ref().unwrap().nodes[0].node_id,
            sw1.to_string()
        );
        assert_eq!(
            calls[0].services,
            crate::config::switch_mtls_services_as_i32(&SwitchMtlsService::default_services())
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_configure_switch_certificate_job_status_completed(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_get_configure_switch_certificate_job_status(Ok(
            MockRmsApi::configure_switch_certificate_job_status_ok("completed"),
        ))
        .await;

        let status =
            NvSwitchManager::get_configure_switch_certificate_job_status(&backend, "cert-job-1")
                .await
                .unwrap();

        assert_eq!(status.state, ConfigureSwitchCertificateState::Completed);
        assert!(status.error.is_none());

        let calls = mock
            .get_configure_switch_certificate_job_status_calls()
            .await;
        assert_eq!(calls[0].job_id, "cert-job-1");
    }

    #[carbide_macros::sqlx_test]
    async fn sw_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, _, _, sw1, sw2) = make_backend(&pool).await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &sw1.to_string(),
        )))
        .await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
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

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, rms::PowerOperation::On as i32);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::SwitchGb200Nvidia as i32));
        assert!(dev0.bmc_endpoint.is_some());
        let dev1 = &calls[1].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev1.node_id, sw2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn sw_power_control_unknown_mac(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, sw2) = make_backend(&pool).await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &sw2.to_string(),
        )))
        .await;

        let eps = vec![make_sw_endpoint(UNKNOWN_MAC), make_sw_endpoint(SW_MAC_2)];
        let results = NvSwitchManager::power_control(&backend, &eps, PowerAction::ForceOff)
            .await
            .unwrap();

        assert!(!results[0].success);
        assert!(results[1].success);

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, rms::PowerOperation::Off as i32);
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_success(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
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

        let calls = mock.apply_firmware_object_calls().await;
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token.as_deref(), Some("token"));
        assert!(calls[0].force_update);
        let filters = component_filters_for(&calls[0], rms::NodeType::SwitchGb200Nvidia);
        assert_eq!(filters, ["BMC", "BIOS"]);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::SwitchGb200Nvidia as i32));
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_fail(
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
        mock.enqueue_apply_switch_system_image(Ok(MockRmsApi::switch_system_image_apply_ok(
            &sw1.to_string(),
            "nvos-job-1",
        )))
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
        assert!(mock.apply_firmware_object_calls().await.is_empty());

        let calls = mock.apply_switch_system_image_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].config_json, r#"{"Id":"fw-json"}"#);
        assert_eq!(calls[0].access_token.as_deref(), Some("token"));
        assert_eq!(calls[0].software_type, "prod");
        assert_eq!(calls[0].hardware_type, "any");
        assert_eq!(calls[0].rack_id, rack_id.to_string());
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, sw1.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::SwitchGb200Nvidia as i32));
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_some());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::SwitchSystemImage(
                "nvos-job-1".to_string()
            )])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_mixed_tracks_both_jobs(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-fw-job",
        )))
        .await;
        mock.enqueue_apply_switch_system_image(Ok(MockRmsApi::switch_system_image_apply_ok(
            &sw1.to_string(),
            "sw-nvos-job",
        )))
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
        assert_eq!(mock.apply_firmware_object_calls().await.len(), 1);
        assert_eq!(mock.apply_switch_system_image_calls().await.len(), 1);

        {
            let jobs = backend.firmware_jobs.lock().unwrap();
            assert_eq!(
                jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
                Some(&vec![
                    RmsTrackedFirmwareJob::FirmwareObject("sw-fw-job".to_string()),
                    RmsTrackedFirmwareJob::SwitchSystemImage("sw-nvos-job".to_string()),
                ])
            );
        }

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::Completed,
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
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &sw1.to_string(),
            "sw-fw-job",
        )))
        .await;
        mock.enqueue_apply_switch_system_image(Ok(MockRmsApi::switch_system_image_apply_fail(
            &sw1.to_string(),
            "bad system image",
        )))
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
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
            rms::FirmwareJobState::Completed,
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

        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
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

        let bundles = NvSwitchManager::list_firmware_bundles(&backend)
            .await
            .unwrap();

        assert!(bundles.is_empty());
    }

    // ---- ComputeTrayManager tests ----

    #[carbide_macros::sqlx_test]
    async fn ct_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ct1, ct2) = make_compute_tray_backend(&pool).await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ct1.to_string(),
        )))
        .await;
        mock.enqueue_batch_set_power_state(Ok(MockRmsApi::batch_set_power_state_ok(
            &ct2.to_string(),
        )))
        .await;

        let eps = vec![make_ct_endpoint(CT_IP_1), make_ct_endpoint(CT_IP_2)];
        let results = ComputeTrayManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.batch_set_power_state_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].operation, rms::PowerOperation::On as i32);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.node_id, ct1.to_string());
        assert_eq!(dev0.rack_id, rack_id.to_string());
        assert_eq!(dev0.r#type, Some(rms::NodeType::ComputeGb200Nvidia as i32));
        assert!(dev0.bmc_endpoint.is_some());
        assert!(dev0.host_endpoint.is_none());
    }

    #[carbide_macros::sqlx_test]
    async fn ct_update_firmware_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ct1, _) = make_compute_tray_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ct1.to_string(),
            "ct-job-1",
        )))
        .await;

        let eps = vec![make_ct_endpoint(CT_IP_1)];
        let results = ComputeTrayManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[ComputeTrayComponent::Bmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        assert!(results[0].success);

        let calls = mock.apply_firmware_object_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].rack_id, rack_id.to_string());
        let filters = component_filters_for(&calls[0], rms::NodeType::ComputeGb200Nvidia);
        assert_eq!(filters, &["BMC".to_owned()]);
        let dev0 = &calls[0].nodes.as_ref().unwrap().nodes[0];
        assert_eq!(dev0.r#type, Some(rms::NodeType::ComputeGb200Nvidia as i32));

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&CT_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&vec![RmsTrackedFirmwareJob::FirmwareObject(
                "ct-job-1".to_string()
            )])
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ct_firmware_status_tracks_job(pool: sqlx::PgPool) {
        let (mock, backend, _, ct1, _) = make_compute_tray_backend(&pool).await;
        mock.enqueue_apply_firmware_object(Ok(MockRmsApi::firmware_object_apply_ok(
            &ct1.to_string(),
            "ct-job-status",
        )))
        .await;

        let eps = vec![make_ct_endpoint(CT_IP_1)];
        ComputeTrayManager::update_firmware(
            &backend,
            &eps,
            r#"{"Id":"fw-json"}"#,
            &[ComputeTrayComponent::Bmc],
            &firmware_update_options(),
        )
        .await
        .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::Completed,
        )))
        .await;

        let statuses = ComputeTrayManager::get_firmware_status(&backend, &eps)
            .await
            .unwrap();

        assert_eq!(statuses[0].state, FirmwareState::Completed);
        assert!(statuses[0].error.is_none());
    }
}
