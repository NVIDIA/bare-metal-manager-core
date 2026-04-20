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

use librms::RmsApi;
use librms::protos::rack_manager as rms;
use mac_address::MacAddress;
use model::component_manager::{
    FirmwareState, NvSwitchComponent, PowerAction, PowerShelfComponent,
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    NvSwitchManager, SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus,
};
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager,
};

/// RMS identity for a device: the node_id and rack_id that RMS needs
/// to address it. Used for both power shelves and switches.
#[derive(Clone)]
struct RmsIdentity {
    node_id: String,
    rack_id: String,
}

pub struct RmsBackend {
    client: Arc<dyn RmsApi>,
    db: PgPool,
    /// Tracks firmware update job IDs keyed by device MAC address.
    firmware_jobs: Mutex<HashMap<MacAddress, String>>,
}

impl std::fmt::Debug for RmsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RmsBackend")
            .field("client", &"<RmsApi>")
            .finish()
    }
}

impl RmsBackend {
    pub fn new(client: Arc<dyn RmsApi>, db: PgPool) -> Self {
        Self {
            client,
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

/// Map PowerShelfComponent to a firmware target name used by RMS.
fn power_shelf_target_name(c: &PowerShelfComponent) -> &'static str {
    match c {
        PowerShelfComponent::Pmc => "pmc",
        PowerShelfComponent::Psu => "psu",
    }
}

#[async_trait::async_trait]
impl PowerShelfManager for RmsBackend {
    fn name(&self) -> &str {
        "rms"
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

            let request = rms::SetPowerStateRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
                operation,
                ..Default::default()
            };

            match self.client.set_power_state(request).await {
                Ok(response) => {
                    let success = response.status == rms::ReturnCode::Success as i32;
                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success,
                        error: if success {
                            None
                        } else {
                            Some("RMS power control failed".into())
                        },
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

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn update_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
        target_version: &str,
        components: &[PowerShelfComponent],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let ids = resolve_power_shelf_identities(&self.db, &macs).await?;
        let firmware_targets: Vec<rms::FirmwareTarget> = components
            .iter()
            .map(|c| rms::FirmwareTarget {
                target: power_shelf_target_name(c).to_owned(),
                filename: target_version.to_owned(),
            })
            .collect();

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

            let request = rms::UpdateNodeFirmwareRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
                firmware_targets: firmware_targets.clone(),
                ..Default::default()
            };

            match self.client.update_node_firmware_async(request).await {
                Ok(response) => {
                    let success = response.status == rms::ReturnCode::Success as i32;

                    if !response.job_id.is_empty() {
                        self.firmware_jobs
                            .lock()
                            .unwrap()
                            .insert(ep.pmc_mac, response.job_id.clone());
                    }

                    results.push(PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success,
                        error: if success {
                            None
                        } else {
                            Some(if response.message.is_empty() {
                                "RMS firmware update failed".to_owned()
                            } else {
                                response.message
                            })
                        },
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
                .map(|ep| (ep.pmc_mac, jobs.get(&ep.pmc_mac).cloned()))
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
                    let state = if response.status == rms::ReturnCode::Success as i32 {
                        map_rms_firmware_job_state(response.job_state)
                    } else {
                        FirmwareState::Unknown
                    };
                    statuses.push(PowerShelfFirmwareUpdateStatus {
                        pmc_mac: *pmc_mac,
                        state,
                        target_version: String::new(),
                        error: if response.error_message.is_empty() {
                            None
                        } else {
                            Some(response.error_message)
                        },
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
}

/// Query all rack firmware IDs from the database.
async fn list_rack_firmware_ids(db: &PgPool) -> Result<Vec<String>, ComponentManagerError> {
    let mut conn = db.acquire().await.map_err(|e| {
        ComponentManagerError::Internal(format!("failed to acquire DB connection: {e}"))
    })?;

    let filter = model::rack_firmware::RackFirmwareSearchFilter {
        only_available: false,
        rack_hardware_type: None,
    };

    let firmwares = db::rack_firmware::list_all(&mut conn, filter)
        .await
        .map_err(|e| {
            ComponentManagerError::Internal(format!("failed to list rack firmware: {e}"))
        })?;

    Ok(firmwares.into_iter().map(|fw| fw.id).collect())
}

/// Map NvSwitchComponent to a firmware target name used by RMS.
fn switch_target_name(c: &NvSwitchComponent) -> &'static str {
    match c {
        NvSwitchComponent::Bmc => "bmc",
        NvSwitchComponent::Cpld => "cpld",
        NvSwitchComponent::Bios => "bios",
        NvSwitchComponent::Nvos => "nvos",
    }
}

#[async_trait::async_trait]
impl NvSwitchManager for RmsBackend {
    fn name(&self) -> &str {
        "rms"
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

            let request = rms::SetPowerStateRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
                operation,
                ..Default::default()
            };

            match self.client.set_power_state(request).await {
                Ok(response) => {
                    let success = response.status == rms::ReturnCode::Success as i32;
                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success,
                        error: if success {
                            None
                        } else {
                            Some("RMS power control failed".into())
                        },
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

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        components: &[NvSwitchComponent],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let ids = resolve_switch_identities(&self.db, &macs).await?;
        let firmware_targets: Vec<rms::FirmwareTarget> = components
            .iter()
            .map(|c| rms::FirmwareTarget {
                target: switch_target_name(c).to_owned(),
                filename: bundle_version.to_owned(),
            })
            .collect();

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

            let request = rms::UpdateNodeFirmwareRequest {
                node_id: identity.node_id.clone(),
                rack_id: identity.rack_id.clone(),
                firmware_targets: firmware_targets.clone(),
                ..Default::default()
            };

            match self.client.update_node_firmware_async(request).await {
                Ok(response) => {
                    let success = response.status == rms::ReturnCode::Success as i32;

                    if !response.job_id.is_empty() {
                        self.firmware_jobs
                            .lock()
                            .unwrap()
                            .insert(ep.bmc_mac, response.job_id.clone());
                    }

                    results.push(SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success,
                        error: if success {
                            None
                        } else {
                            Some(if response.message.is_empty() {
                                "RMS firmware update failed".to_owned()
                            } else {
                                response.message
                            })
                        },
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_mac = %ep.bmc_mac,
                        error = %e,
                        "RMS firmware update failed for switch"
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

    #[instrument(skip(self), fields(backend = "rms"))]
    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        let endpoint_jobs: Vec<(MacAddress, Option<String>)> = {
            let jobs = self.firmware_jobs.lock().unwrap();
            endpoints
                .iter()
                .map(|ep| (ep.bmc_mac, jobs.get(&ep.bmc_mac).cloned()))
                .collect()
        };

        let mut statuses = Vec::with_capacity(endpoints.len());

        for (bmc_mac, job_id) in &endpoint_jobs {
            let Some(job_id) = job_id else {
                statuses.push(SwitchFirmwareUpdateStatus {
                    bmc_mac: *bmc_mac,
                    state: FirmwareState::Unknown,
                    target_version: String::new(),
                    error: Some("no firmware job tracked for this switch".into()),
                });
                continue;
            };

            let request = rms::GetFirmwareJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            };

            match self.client.get_firmware_job_status(request).await {
                Ok(response) => {
                    let state = if response.status == rms::ReturnCode::Success as i32 {
                        map_rms_firmware_job_state(response.job_state)
                    } else {
                        FirmwareState::Unknown
                    };
                    statuses.push(SwitchFirmwareUpdateStatus {
                        bmc_mac: *bmc_mac,
                        state,
                        target_version: String::new(),
                        error: if response.error_message.is_empty() {
                            None
                        } else {
                            Some(response.error_message)
                        },
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        bmc_mac = %bmc_mac,
                        job_id = %job_id,
                        error = %e,
                        "RMS firmware job status query failed"
                    );
                    statuses.push(SwitchFirmwareUpdateStatus {
                        bmc_mac: *bmc_mac,
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
        list_rack_firmware_ids(&self.db).await
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
    fn power_shelf_target_names() {
        assert_eq!(power_shelf_target_name(&PowerShelfComponent::Pmc), "pmc");
        assert_eq!(power_shelf_target_name(&PowerShelfComponent::Psu), "psu");
    }

    #[test]
    fn switch_target_names() {
        assert_eq!(switch_target_name(&NvSwitchComponent::Bmc), "bmc");
        assert_eq!(switch_target_name(&NvSwitchComponent::Cpld), "cpld");
        assert_eq!(switch_target_name(&NvSwitchComponent::Bios), "bios");
        assert_eq!(switch_target_name(&NvSwitchComponent::Nvos), "nvos");
    }

    // ---- Test helpers ----

    fn make_ps_endpoint(mac: &str) -> PowerShelfEndpoint {
        PowerShelfEndpoint {
            pmc_ip: "10.0.0.1".parse().unwrap(),
            pmc_mac: mac.parse().unwrap(),
            pmc_vendor: PowerShelfVendor::Liteon,
        }
    }

    fn make_sw_endpoint(mac: &str) -> SwitchEndpoint {
        SwitchEndpoint {
            bmc_ip: "10.0.0.1".parse().unwrap(),
            bmc_mac: mac.parse().unwrap(),
            nvos_ip: "10.0.0.2".parse().unwrap(),
            nvos_mac: "11:22:33:44:55:66".parse().unwrap(),
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
        let backend = RmsBackend::new(mock.clone(), pool.clone());
        (mock, backend, rack_id, ps1, ps2, sw1, sw2)
    }

    // ---- PowerShelfManager tests ----

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = PowerShelfManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].node_id, ps1.to_string());
        assert_eq!(calls[0].rack_id, rack_id.to_string());
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOn as i32);
        assert_eq!(calls[1].node_id, ps2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn ps_power_control_partial_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_fail()))
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
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Err(librms::RackManagerError::ApiInvocationError(
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
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = vec![make_ps_endpoint(UNKNOWN_MAC), make_ps_endpoint(PS_MAC_2)];
        let results =
            PowerShelfManager::power_control(&backend, &eps, PowerAction::GracefulShutdown)
                .await
                .unwrap();

        assert!(!results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOff as i32);
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_success(pool: sqlx::PgPool) {
        let (mock, backend, rack_id, ps1, _ps2, _, _) = make_backend(&pool).await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-aaa")))
            .await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-bbb")))
            .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1), make_ps_endpoint(PS_MAC_2)];
        let results = backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.update_node_firmware_async_calls().await;
        assert_eq!(calls[0].firmware_targets[0].target, "pmc");
        assert_eq!(calls[0].node_id, ps1.to_string());
        assert_eq!(calls[0].rack_id, rack_id.to_string());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&PS_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&"job-aaa".to_string())
        );
        assert_eq!(
            jobs.get(&PS_MAC_2.parse::<MacAddress>().unwrap()),
            Some(&"job-bbb".to_string())
        );
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_multiple_components(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-1")))
            .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend
            .update_firmware(
                &eps,
                "fw-2.0.0",
                &[PowerShelfComponent::Pmc, PowerShelfComponent::Psu],
            )
            .await
            .unwrap();

        assert!(results[0].success);

        let calls = mock.update_node_firmware_async_calls().await;
        assert_eq!(calls[0].firmware_targets.len(), 2);
        assert_eq!(calls[0].firmware_targets[0].target, "pmc");
        assert_eq!(calls[0].firmware_targets[1].target, "psu");
    }

    #[carbide_macros::sqlx_test]
    async fn ps_update_firmware_failure(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_fail(
            "bad firmware file",
        )))
        .await;

        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        let results = backend
            .update_firmware(&eps, "fw-bad", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        assert!(!results[0].success);
        assert_eq!(results[0].error.as_deref(), Some("bad firmware file"));
    }

    #[carbide_macros::sqlx_test]
    async fn ps_firmware_status_running(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-xyz")))
            .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
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
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-done")))
            .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
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
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-fail")))
            .await;
        let eps = vec![make_ps_endpoint(PS_MAC_1)];
        backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
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
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1), make_sw_endpoint(SW_MAC_2)];
        let results = NvSwitchManager::power_control(&backend, &eps, PowerAction::On)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls[0].node_id, sw1.to_string());
        assert_eq!(calls[0].rack_id, rack_id.to_string());
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOn as i32);
        assert_eq!(calls[1].node_id, sw2.to_string());
    }

    #[carbide_macros::sqlx_test]
    async fn sw_power_control_unknown_mac(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = vec![make_sw_endpoint(UNKNOWN_MAC), make_sw_endpoint(SW_MAC_2)];
        let results = NvSwitchManager::power_control(&backend, &eps, PowerAction::ForceOff)
            .await
            .unwrap();

        assert!(!results[0].success);
        assert!(results[1].success);

        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls.len(), 1);
    }

    #[carbide_macros::sqlx_test]
    async fn sw_queue_firmware_updates_success(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, sw1, _) = make_backend(&pool).await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("sw-job-1")))
            .await;

        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        let results = backend
            .queue_firmware_updates(
                &eps,
                "fw-2.0.0",
                &[NvSwitchComponent::Bmc, NvSwitchComponent::Bios],
            )
            .await
            .unwrap();

        assert!(results[0].success);

        let calls = mock.update_node_firmware_async_calls().await;
        assert_eq!(calls[0].firmware_targets[0].target, "bmc");
        assert_eq!(calls[0].firmware_targets[1].target, "bios");
        assert_eq!(calls[0].node_id, sw1.to_string());

        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&SW_MAC_1.parse::<MacAddress>().unwrap()),
            Some(&"sw-job-1".to_string())
        );
    }

    #[carbide_macros::sqlx_test]
    async fn sw_firmware_status(pool: sqlx::PgPool) {
        let (mock, backend, _, _, _, _, _) = make_backend(&pool).await;

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("sw-job-2")))
            .await;
        let eps = vec![make_sw_endpoint(SW_MAC_1)];
        backend
            .queue_firmware_updates(&eps, "fw-1.0", &[NvSwitchComponent::Bmc])
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
    async fn list_firmware_bundles_empty_db(pool: sqlx::PgPool) {
        let (_mock, backend, _, _, _, _, _) = make_backend(&pool).await;
        let bundles = backend.list_firmware_bundles().await.unwrap();
        assert!(bundles.is_empty());
    }
}
