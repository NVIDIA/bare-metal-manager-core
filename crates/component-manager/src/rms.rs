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

use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use librms::RmsApi;
use librms::protos::rack_manager as rms;
use mac_address::MacAddress;
use sqlx::PgPool;
use tracing::instrument;

use crate::error::ComponentManagerError;
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager,
};
use crate::types::{FirmwareState, PowerAction, PowerShelfComponent};

/// RMS identity for a power shelf: the node_id and rack_id that RMS
/// needs to address a device.
#[derive(Clone)]
struct RmsIdentity {
    node_id: String,
    rack_id: String,
}

pub struct RmsBackend {
    client: Arc<dyn RmsApi>,
    db: PgPool,
    /// Tracks firmware update job IDs keyed by PMC MAC address.
    firmware_jobs: Mutex<HashMap<MacAddress, String>>,
    /// Pre-set identity overrides for testing (bypasses DB lookup).
    #[cfg(test)]
    identity_overrides: Option<HashMap<MacAddress, RmsIdentity>>,
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
            #[cfg(test)]
            identity_overrides: None,
        }
    }

    /// Resolve identities from the override map (test) or the database (prod).
    async fn resolve_identities(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<HashMap<MacAddress, RmsIdentity>, ComponentManagerError> {
        #[cfg(test)]
        if let Some(overrides) = &self.identity_overrides {
            return Ok(overrides.clone());
        }
        resolve_rms_identities(&self.db, endpoints).await
    }
}

/// Resolve PMC MAC addresses to RMS identities (node_id, rack_id) via the
/// database. Uses the `bmc_mac_address` column on `power_shelves`, which was
/// a complete oversight on my part not adding like we had for `switches`,
/// sorry!
async fn resolve_rms_identities(
    db: &PgPool,
    endpoints: &[PowerShelfEndpoint],
) -> Result<HashMap<MacAddress, RmsIdentity>, ComponentManagerError> {
    let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();

    let rows: Vec<(PowerShelfId, MacAddress, Option<RackId>)> = sqlx::query_as(
        r#"
        SELECT ps.id, ps.bmc_mac_address, ps.rack_id
        FROM power_shelves ps
        WHERE ps.bmc_mac_address = ANY($1)
        "#,
    )
    .bind(&macs)
    .fetch_all(db)
    .await
    .map_err(|e| {
        ComponentManagerError::Internal(format!("failed to resolve RMS identities: {e}"))
    })?;

    let mut map = HashMap::with_capacity(rows.len());
    for (ps_id, mac, rack_id) in rows {
        let Some(rack_id) = rack_id else {
            tracing::warn!(pmc_mac = %mac, "power shelf has no rack_id, skipping");
            continue;
        };
        map.insert(
            mac,
            RmsIdentity {
                node_id: ps_id.to_string(),
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
fn component_target_name(c: &PowerShelfComponent) -> &'static str {
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
        let ids = self.resolve_identities(endpoints).await?;
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
        let ids = self.resolve_identities(endpoints).await?;
        let firmware_targets: Vec<rms::FirmwareTarget> = components
            .iter()
            .map(|c| rms::FirmwareTarget {
                target: component_target_name(c).to_owned(),
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
        let ids = self.resolve_identities(endpoints).await?;
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

#[cfg(test)]
mod tests {
    use api_test_helper::mock_rms::MockRmsApi;

    use super::*;
    use crate::power_shelf_manager::PowerShelfVendor;

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
    fn component_target_names() {
        assert_eq!(component_target_name(&PowerShelfComponent::Pmc), "pmc");
        assert_eq!(component_target_name(&PowerShelfComponent::Psu), "psu");
    }

    // ---- Test helpers ----

    fn make_endpoint(mac: &str) -> PowerShelfEndpoint {
        PowerShelfEndpoint {
            pmc_ip: "10.0.0.1".parse().unwrap(),
            pmc_mac: mac.parse().unwrap(),
            pmc_vendor: PowerShelfVendor::Liteon,
        }
    }

    fn make_endpoints() -> Vec<PowerShelfEndpoint> {
        vec![
            make_endpoint("AA:BB:CC:DD:EE:01"),
            make_endpoint("AA:BB:CC:DD:EE:02"),
        ]
    }

    /// Build identity overrides that map our test MACs to known RMS IDs.
    fn test_identities() -> HashMap<MacAddress, RmsIdentity> {
        let mut map = HashMap::new();
        map.insert(
            "AA:BB:CC:DD:EE:01".parse().unwrap(),
            RmsIdentity {
                node_id: "ps-001".into(),
                rack_id: "rack-001".into(),
            },
        );
        map.insert(
            "AA:BB:CC:DD:EE:02".parse().unwrap(),
            RmsIdentity {
                node_id: "ps-002".into(),
                rack_id: "rack-001".into(),
            },
        );
        map
    }

    /// Create a backend backed by the shared mock with pre-set identity
    /// overrides (no real database needed).
    fn make_backend() -> (Arc<MockRmsApi>, RmsBackend) {
        let mock = Arc::new(MockRmsApi::new());
        // connect_lazy doesn't actually connect — the identity overrides
        // bypass the DB so this pool is never used.
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test@localhost/fake")
            .unwrap();
        let mut backend = RmsBackend::new(mock.clone(), db);
        backend.identity_overrides = Some(test_identities());
        (mock, backend)
    }

    #[tokio::test]
    async fn power_control_success() {
        let (mock, backend) = make_backend();
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = make_endpoints();
        let results = backend.power_control(&eps, PowerAction::On).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);
        assert!(results[0].error.is_none());

        // Verify correct requests were sent
        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].node_id, "ps-001");
        assert_eq!(calls[0].rack_id, "rack-001");
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOn as i32);
        assert_eq!(calls[1].node_id, "ps-002");
    }

    #[tokio::test]
    async fn power_control_partial_failure() {
        let (mock, backend) = make_backend();
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_fail()))
            .await;

        let eps = make_endpoints();
        let results = backend.power_control(&eps, PowerAction::On).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(!results[1].success);
        assert!(results[1].error.is_some());
    }

    #[tokio::test]
    async fn power_control_rms_transport_error() {
        let (mock, backend) = make_backend();
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;
        mock.enqueue_set_power_state(Err(librms::RackManagerError::ApiInvocationError(
            tonic::Status::unavailable("connection refused"),
        )))
        .await;

        let eps = make_endpoints();
        let results = backend.power_control(&eps, PowerAction::On).await.unwrap();

        assert_eq!(results.len(), 2);
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

    #[tokio::test]
    async fn power_control_unknown_mac_skips_endpoint() {
        let (mock, backend) = make_backend();
        mock.enqueue_set_power_state(Ok(MockRmsApi::power_ok()))
            .await;

        let eps = vec![
            make_endpoint("FF:FF:FF:FF:FF:FF"), // not in identity overrides
            make_endpoint("AA:BB:CC:DD:EE:02"),
        ];
        let results = backend
            .power_control(&eps, PowerAction::GracefulShutdown)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].success); // skipped — not found in DB
        assert!(results[1].success); // called RMS

        let calls = mock.set_power_state_calls().await;
        assert_eq!(calls.len(), 1); // only one RMS call made
        assert_eq!(calls[0].operation, rms::PowerOperation::PowerOff as i32);
    }

    #[tokio::test]
    async fn update_firmware_success_stores_job_ids() {
        let (mock, backend) = make_backend();
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-aaa")))
            .await;
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-bbb")))
            .await;

        let eps = make_endpoints();
        let results = backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);

        // Verify firmware targets were built correctly
        let calls = mock.update_node_firmware_async_calls().await;
        assert_eq!(calls[0].firmware_targets.len(), 1);
        assert_eq!(calls[0].firmware_targets[0].target, "pmc");
        assert_eq!(calls[0].firmware_targets[0].filename, "fw-1.0.0");
        assert_eq!(calls[0].node_id, "ps-001");
        assert_eq!(calls[0].rack_id, "rack-001");

        // Verify job IDs were stored for later status queries
        let jobs = backend.firmware_jobs.lock().unwrap();
        assert_eq!(
            jobs.get(&"AA:BB:CC:DD:EE:01".parse::<MacAddress>().unwrap()),
            Some(&"job-aaa".to_string()),
        );
        assert_eq!(
            jobs.get(&"AA:BB:CC:DD:EE:02".parse::<MacAddress>().unwrap()),
            Some(&"job-bbb".to_string()),
        );
    }

    #[tokio::test]
    async fn update_firmware_multiple_components() {
        let (mock, backend) = make_backend();
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-1")))
            .await;

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
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

    #[tokio::test]
    async fn update_firmware_failure_reports_message() {
        let (mock, backend) = make_backend();
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_fail(
            "bad firmware file",
        )))
        .await;

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        let results = backend
            .update_firmware(&eps, "fw-bad", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        assert!(!results[0].success);
        assert_eq!(results[0].error.as_deref(), Some("bad firmware file"));
    }

    #[tokio::test]
    async fn get_firmware_status_returns_job_state() {
        let (mock, backend) = make_backend();

        // First, do a firmware update to populate job tracking
        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-xyz")))
            .await;
        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        // Now query status
        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobRunning,
        )))
        .await;

        let statuses = backend.get_firmware_status(&eps).await.unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FirmwareState::InProgress);
        assert!(statuses[0].error.is_none());

        // Verify the correct job_id was sent
        let calls = mock.get_firmware_job_status_calls().await;
        assert_eq!(calls[0].job_id, "job-xyz");
    }

    #[tokio::test]
    async fn get_firmware_status_no_tracked_job() {
        let (_mock, backend) = make_backend();

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        let statuses = backend.get_firmware_status(&eps).await.unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FirmwareState::Unknown);
        assert!(
            statuses[0]
                .error
                .as_ref()
                .unwrap()
                .contains("no firmware job")
        );
    }

    #[tokio::test]
    async fn get_firmware_status_completed() {
        let (mock, backend) = make_backend();

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-done")))
            .await;
        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        backend
            .update_firmware(&eps, "fw-1.0.0", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        mock.enqueue_get_firmware_job_status(Ok(MockRmsApi::firmware_job_status_ok(
            rms::FirmwareJobState::FwJobCompleted,
        )))
        .await;

        let statuses = backend.get_firmware_status(&eps).await.unwrap();
        assert_eq!(statuses[0].state, FirmwareState::Completed);
    }

    #[tokio::test]
    async fn get_firmware_status_failed_with_error_message() {
        let (mock, backend) = make_backend();

        mock.enqueue_update_node_firmware_async(Ok(MockRmsApi::firmware_update_ok("job-fail")))
            .await;
        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
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

        let statuses = backend.get_firmware_status(&eps).await.unwrap();
        assert_eq!(statuses[0].state, FirmwareState::Failed);
        assert_eq!(statuses[0].error.as_deref(), Some("checksum mismatch"));
    }

    #[tokio::test]
    async fn list_firmware_returns_versions() {
        let (mock, backend) = make_backend();
        mock.enqueue_get_node_firmware_inventory(Ok(MockRmsApi::firmware_inventory_ok(&[
            ("PMC", "1.2.3"),
            ("PSU", "4.5.6"),
        ])))
        .await;

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].versions, vec!["1.2.3", "4.5.6"]);
        assert!(results[0].error.is_none());

        let calls = mock.get_node_firmware_inventory_calls().await;
        assert_eq!(calls[0].node_id, "ps-001");
        assert_eq!(calls[0].rack_id, "rack-001");
    }

    #[tokio::test]
    async fn list_firmware_rms_failure() {
        let (mock, backend) = make_backend();
        mock.enqueue_get_node_firmware_inventory(Ok(rms::GetNodeFirmwareInventoryResponse {
            status: rms::ReturnCode::Failure as i32,
            ..Default::default()
        }))
        .await;

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.is_some());
    }

    #[tokio::test]
    async fn list_firmware_transport_error() {
        let (mock, backend) = make_backend();
        mock.enqueue_get_node_firmware_inventory(Err(
            librms::RackManagerError::ApiInvocationError(tonic::Status::unavailable("down")),
        ))
        .await;

        let eps = vec![make_endpoint("AA:BB:CC:DD:EE:01")];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.as_ref().unwrap().contains("down"));
    }

    #[tokio::test]
    async fn list_firmware_unknown_mac() {
        let (_mock, backend) = make_backend();

        let eps = vec![make_endpoint("FF:FF:FF:FF:FF:FF")];
        let results = backend.list_firmware(&eps).await.unwrap();

        assert!(results[0].versions.is_empty());
        assert!(results[0].error.is_some());
    }

    // ---- DB-backed integration tests ----
    //
    // These use a real PostgreSQL database to verify the SQL join in
    // `resolve_rms_identities` works end-to-end.

    mod db_tests {
        use carbide_uuid::power_shelf::{PowerShelfIdSource, PowerShelfType};
        use carbide_uuid::rack::RackId;
        use model::expected_power_shelf::ExpectedPowerShelf;
        use model::metadata::Metadata;
        use model::power_shelf::{NewPowerShelf, PowerShelfConfig};
        use model::rack::RackConfig;

        use super::*;

        /// Create a deterministic PowerShelfId from a label string.
        fn test_power_shelf_id(label: &str) -> PowerShelfId {
            let mut hash = [0u8; 32];
            let bytes = label.as_bytes();
            hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
            PowerShelfId::new(
                PowerShelfIdSource::ProductBoardChassisSerial,
                hash,
                PowerShelfType::Rack,
            )
        }

        /// Insert a power shelf with bmc_mac_address set. Also creates the
        /// expected_power_shelf row (required by FK constraint).
        async fn seed_power_shelf(
            txn: &mut sqlx::PgConnection,
            mac: &str,
            label: &str,
            rack_id: Option<&RackId>,
        ) -> PowerShelfId {
            let ps_id = test_power_shelf_id(label);
            let mac: MacAddress = mac.parse().unwrap();

            // expected_power_shelf must exist first (FK on bmc_mac_address)
            db::expected_power_shelf::create(
                &mut *txn,
                ExpectedPowerShelf {
                    expected_power_shelf_id: None,
                    bmc_mac_address: mac,
                    serial_number: label.to_owned(),
                    bmc_username: "admin".into(),
                    bmc_password: "pass".into(),
                    bmc_ip_address: None,
                    metadata: Metadata::default(),
                    rack_id: rack_id.cloned(),
                    bmc_retain_credentials: None,
                },
            )
            .await
            .expect("failed to create expected power shelf");

            let new_ps = NewPowerShelf {
                id: ps_id,
                config: PowerShelfConfig {
                    name: label.to_owned(),
                    capacity: None,
                    voltage: None,
                },
                metadata: Some(Metadata::default()),
                rack_id: rack_id.cloned(),
            };
            db::power_shelf::create(&mut *txn, &new_ps)
                .await
                .expect("failed to create power shelf");

            sqlx::query("UPDATE power_shelves SET bmc_mac_address = $1 WHERE id = $2")
                .bind(mac)
                .bind(ps_id)
                .execute(&mut *txn)
                .await
                .expect("failed to set bmc_mac_address");

            ps_id
        }

        #[carbide_macros::sqlx_test]
        async fn resolve_identities_from_database(pool: sqlx::PgPool) {
            let mut txn = pool.begin().await.unwrap();

            let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
            db::rack::create(&mut txn, &rack_id, &RackConfig::default(), None)
                .await
                .expect("failed to create rack");

            let mac = "AA:BB:CC:DD:EE:01";
            let ps_id = seed_power_shelf(&mut txn, mac, "PS-SERIAL-001", Some(&rack_id)).await;

            txn.commit().await.unwrap();

            // Build backend with real DB pool (no identity overrides)
            let mock = Arc::new(MockRmsApi::new());
            let backend = RmsBackend::new(mock.clone(), pool.clone());

            mock.enqueue_get_node_firmware_inventory(Ok(MockRmsApi::firmware_inventory_ok(&[(
                "PMC", "1.0.0",
            )])))
            .await;

            let eps = vec![make_endpoint(mac)];
            let results = backend.list_firmware(&eps).await.unwrap();

            // Verify the firmware call succeeded (identity was resolved)
            assert_eq!(results.len(), 1);
            assert!(results[0].error.is_none());
            assert_eq!(results[0].versions, vec!["1.0.0"]);

            // Verify the correct node_id and rack_id were sent to RMS
            let calls = mock.get_node_firmware_inventory_calls().await;
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].node_id, ps_id.to_string());
            assert_eq!(calls[0].rack_id, rack_id.to_string());
        }

        #[carbide_macros::sqlx_test]
        async fn resolve_identities_missing_rack_id_skips_endpoint(pool: sqlx::PgPool) {
            let mut txn = pool.begin().await.unwrap();

            let mac = "AA:BB:CC:DD:EE:02";
            seed_power_shelf(&mut txn, mac, "PS-NO-RACK", None).await;

            txn.commit().await.unwrap();

            let mock = Arc::new(MockRmsApi::new());
            let backend = RmsBackend::new(mock, pool.clone());

            let eps = vec![make_endpoint(mac)];
            let results = backend.list_firmware(&eps).await.unwrap();

            // Endpoint should be skipped — power shelf has no rack_id
            assert_eq!(results.len(), 1);
            assert!(results[0].error.is_some());
            assert!(results[0].versions.is_empty());
        }
    }
}
