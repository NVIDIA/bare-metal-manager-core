// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A Component Manager `PowerShelfManager` implementation that routes write
//! operations to the per-power-shelf state controller for power control (by
//! writing `power_shelves.power_shelf_maintenance_requested`) and to the
//! rack state controller for firmware upgrade (by writing a
//! `MaintenanceScope` onto `racks.config.maintenance_requested`). Reads are
//! passed through to the wrapped direct backend.

use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use db::ObjectColumnFilter;
use mac_address::MacAddress;
use model::component_manager::{PowerAction, PowerShelfComponent};
use model::power_shelf::PowerShelfMaintenanceOperation;
use model::rack::{MaintenanceActivity, MaintenanceScope};
use sqlx::PgPool;
use tracing::instrument;

use super::unique_rack_id;
use crate::error::ComponentManagerError;
use crate::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfFirmwareVersions, PowerShelfManager,
};

const UNKNOWN_MAC_ERROR: &str = "no power shelf row found for this BMC MAC address";
const DEVICE_KIND: &str = "power shelves";

/// Initiator string recorded on `power_shelf_maintenance_requested` rows
/// originating from a Component Manager `power_control` call. The per-shelf
/// state controller surfaces this in its logs and reports.
const COMPONENT_MANAGER_INITIATOR: &str = "component-manager";

/// Map a `PowerAction` into the per-power-shelf maintenance operation set
/// (`PowerOn` / `PowerOff`). The per-shelf state machine does not model
/// reboots or AC powercycles, so those actions are rejected up-front.
fn map_power_action_to_shelf_operation(
    action: PowerAction,
) -> Result<PowerShelfMaintenanceOperation, ComponentManagerError> {
    match action {
        PowerAction::On => Ok(PowerShelfMaintenanceOperation::PowerOn),
        PowerAction::GracefulShutdown | PowerAction::ForceOff => {
            Ok(PowerShelfMaintenanceOperation::PowerOff)
        }
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            Err(ComponentManagerError::InvalidArgument(format!(
                "power action {action:?} is not supported on power shelves; \
             only On, GracefulShutdown and ForceOff are accepted"
            )))
        }
    }
}

/// Wraps a direct `PowerShelfManager` backend (e.g., `RmsBackend`,
/// `PsmBackend`) and routes state-changing operations through the rack state
/// controller instead of dispatching them directly.
///
/// `direct` is deliberately public so the rack state controller can reach
/// through to it for the real dispatch.
pub struct StateControllerPowerShelf {
    db: PgPool,
    pub direct: Arc<dyn PowerShelfManager>,
}

impl std::fmt::Debug for StateControllerPowerShelf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateControllerPowerShelf")
            .field("direct", &self.direct.name())
            .finish()
    }
}

impl StateControllerPowerShelf {
    pub fn new(db: PgPool, direct: Arc<dyn PowerShelfManager>) -> Self {
        Self { db, direct }
    }

    /// Resolve endpoints to `(PowerShelfId, BMC MAC)` pairs and return the
    /// per-endpoint result vector along with the resolved IDs. Endpoints
    /// whose MAC does not map to any known power shelf row are flagged as a
    /// per-endpoint error.
    async fn resolve_endpoints(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<EndpointResolution, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.pmc_mac).collect();
        let resolved = db::power_shelf::find_ids_by_bmc_macs(&self.db, &macs)
            .await
            .map_err(|e| {
                ComponentManagerError::Internal(format!(
                    "failed to resolve power shelf IDs by MAC: {e}"
                ))
            })?;

        let id_by_mac: HashMap<MacAddress, (PowerShelfId, Option<RackId>)> = resolved
            .into_iter()
            .map(|r| (r.bmc_mac_address, (r.id, r.rack_id)))
            .collect();

        Ok(EndpointResolution { id_by_mac })
    }

    /// Issue per-power-shelf maintenance requests (`PowerOn` / `PowerOff`)
    /// for the resolved endpoints. Each request is written to
    /// `power_shelves.power_shelf_maintenance_requested`; the per-shelf
    /// state controller will then drive the actual transition through the
    /// configured direct backend.
    async fn write_per_shelf_maintenance(
        &self,
        endpoints: &[PowerShelfEndpoint],
        operation: PowerShelfMaintenanceOperation,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let resolution = self.resolve_endpoints(endpoints).await?;

        // All MACs unknown: nothing to write; return per-endpoint errors.
        if resolution.id_by_mac.is_empty() {
            return Ok(endpoints
                .iter()
                .map(|ep| unknown_mac_result(ep.pmc_mac))
                .collect());
        }

        let mut txn = self.db.begin().await.map_err(|e| {
            ComponentManagerError::Internal(format!("failed to begin transaction: {e}"))
        })?;

        for ep in endpoints {
            if let Some((id, _)) = resolution.id_by_mac.get(&ep.pmc_mac) {
                db::power_shelf::set_power_shelf_maintenance_requested(
                    txn.as_mut(),
                    *id,
                    COMPONENT_MANAGER_INITIATOR,
                    operation,
                )
                .await
                .map_err(|e| {
                    ComponentManagerError::Internal(format!(
                        "failed to write power shelf maintenance request for {id}: {e}"
                    ))
                })?;
            }
        }

        txn.commit().await.map_err(|e| {
            ComponentManagerError::Internal(format!("failed to commit transaction: {e}"))
        })?;

        Ok(endpoints
            .iter()
            .map(|ep| {
                if resolution.id_by_mac.contains_key(&ep.pmc_mac) {
                    PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: true,
                        error: None,
                    }
                } else {
                    unknown_mac_result(ep.pmc_mac)
                }
            })
            .collect())
    }

    /// Resolve endpoints, preflight, write a rack-level `MaintenanceScope`,
    /// and return the per-endpoint result vector. Used by `update_firmware`
    /// (firmware upgrade is a rack-scoped activity).
    async fn write_scope(
        &self,
        endpoints: &[PowerShelfEndpoint],
        activity: MaintenanceActivity,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let resolution = self.resolve_endpoints(endpoints).await?;

        // All MACs unknown: no rack to target; just return per-endpoint errors.
        if resolution.id_by_mac.is_empty() {
            return Ok(endpoints
                .iter()
                .map(|ep| unknown_mac_result(ep.pmc_mac))
                .collect());
        }

        let rack_id = unique_rack_id(
            endpoints.iter().filter_map(|ep| {
                resolution
                    .id_by_mac
                    .get(&ep.pmc_mac)
                    .map(|(_, rack)| rack.as_ref())
            }),
            DEVICE_KIND,
        )?;

        let power_shelf_ids: Vec<PowerShelfId> = endpoints
            .iter()
            .filter_map(|ep| resolution.id_by_mac.get(&ep.pmc_mac).map(|(id, _)| *id))
            .collect();

        self.persist_scope(&rack_id, power_shelf_ids, activity)
            .await?;

        Ok(endpoints
            .iter()
            .map(|ep| {
                if resolution.id_by_mac.contains_key(&ep.pmc_mac) {
                    PowerShelfComponentResult {
                        pmc_mac: ep.pmc_mac,
                        success: true,
                        error: None,
                    }
                } else {
                    unknown_mac_result(ep.pmc_mac)
                }
            })
            .collect())
    }

    async fn persist_scope(
        &self,
        rack_id: &RackId,
        power_shelf_ids: Vec<PowerShelfId>,
        activity: MaintenanceActivity,
    ) -> Result<(), ComponentManagerError> {
        let mut txn = self.db.begin().await.map_err(|e| {
            ComponentManagerError::Internal(format!("failed to begin transaction: {e}"))
        })?;

        let rack = db::rack::find_by(
            txn.as_mut(),
            ObjectColumnFilter::One(db::rack::IdColumn, rack_id),
        )
        .await
        .map_err(|e| ComponentManagerError::Internal(format!("failed to load rack: {e}")))?
        .pop()
        .ok_or_else(|| ComponentManagerError::NotFound(format!("rack {rack_id} not found")))?;

        rack.check_accepts_maintenance()
            .map_err(|r| ComponentManagerError::InvalidArgument(format!("rack {rack_id}: {r}")))?;

        let scope = MaintenanceScope {
            machine_ids: vec![],
            switch_ids: vec![],
            power_shelf_ids,
            activities: vec![activity],
        };

        let mut new_config = rack.config.clone();
        new_config.maintenance_requested = Some(scope);
        db::rack::update(txn.as_mut(), rack_id, &new_config)
            .await
            .map_err(|e| {
                ComponentManagerError::Internal(format!("failed to write maintenance scope: {e}"))
            })?;

        txn.commit().await.map_err(|e| {
            ComponentManagerError::Internal(format!("failed to commit transaction: {e}"))
        })?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl PowerShelfManager for StateControllerPowerShelf {
    fn name(&self) -> &str {
        "state-controller"
    }

    #[instrument(skip(self), fields(backend = "state-controller"))]
    async fn power_control(
        &self,
        endpoints: &[PowerShelfEndpoint],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let operation = map_power_action_to_shelf_operation(action)?;
        self.write_per_shelf_maintenance(endpoints, operation).await
    }

    #[instrument(skip(self), fields(backend = "state-controller"))]
    async fn update_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
        target_version: &str,
        _components: &[PowerShelfComponent],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let firmware_version = if target_version.is_empty() {
            None
        } else {
            Some(target_version.to_owned())
        };
        self.write_scope(
            endpoints,
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version,
                components: vec![],
                force_update: false,
            },
        )
        .await
    }

    async fn get_firmware_status(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        self.direct.get_firmware_status(endpoints).await
    }

    async fn list_firmware(
        &self,
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareVersions>, ComponentManagerError> {
        self.direct.list_firmware(endpoints).await
    }
}

fn unknown_mac_result(pmc_mac: MacAddress) -> PowerShelfComponentResult {
    PowerShelfComponentResult {
        pmc_mac,
        success: false,
        error: Some(UNKNOWN_MAC_ERROR.into()),
    }
}

/// Lookup result built by [`StateControllerPowerShelf::resolve_endpoints`].
/// Owning this map separately keeps `power_control` (per-shelf) and
/// `update_firmware` (rack-scoped) sharing the same MAC -> ID resolution
/// without duplicating the `find_ids_by_bmc_macs` round-trip.
struct EndpointResolution {
    id_by_mac: HashMap<MacAddress, (PowerShelfId, Option<RackId>)>,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use forge_secrets::credentials::Credentials;
    use model::power_shelf::PowerShelfMaintenanceRequest;
    use model::rack::{FirmwareUpgradeState, RackMaintenanceState};

    use super::*;
    use crate::power_shelf_manager::PowerShelfVendor;
    use crate::test_support::{PS_MAC_1, PS_MAC_2, UNKNOWN_MAC, seed_test_data, set_rack_state};

    /// Minimal recording direct backend that only records calls.
    /// Tests use it to assert we only hit the direct for reads.
    #[derive(Debug, Default)]
    struct RecordingDirect {
        power_control_calls: Mutex<usize>,
        update_firmware_calls: Mutex<usize>,
        get_firmware_status_calls: Mutex<usize>,
        list_firmware_calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl PowerShelfManager for RecordingDirect {
        fn name(&self) -> &str {
            "recording"
        }

        async fn power_control(
            &self,
            _endpoints: &[PowerShelfEndpoint],
            _action: PowerAction,
        ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
            *self.power_control_calls.lock().unwrap() += 1;
            Ok(vec![])
        }

        async fn update_firmware(
            &self,
            _endpoints: &[PowerShelfEndpoint],
            _target_version: &str,
            _components: &[PowerShelfComponent],
        ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
            *self.update_firmware_calls.lock().unwrap() += 1;
            Ok(vec![])
        }

        async fn get_firmware_status(
            &self,
            endpoints: &[PowerShelfEndpoint],
        ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
            *self.get_firmware_status_calls.lock().unwrap() += 1;
            Ok(endpoints
                .iter()
                .map(|ep| PowerShelfFirmwareUpdateStatus {
                    pmc_mac: ep.pmc_mac,
                    state: model::component_manager::FirmwareState::Unknown,
                    target_version: String::new(),
                    error: None,
                })
                .collect())
        }

        async fn list_firmware(
            &self,
            endpoints: &[PowerShelfEndpoint],
        ) -> Result<Vec<PowerShelfFirmwareVersions>, ComponentManagerError> {
            *self.list_firmware_calls.lock().unwrap() += 1;
            Ok(endpoints
                .iter()
                .map(|ep| PowerShelfFirmwareVersions {
                    pmc_mac: ep.pmc_mac,
                    versions: vec!["1.0".into()],
                    error: None,
                })
                .collect())
        }
    }

    fn make_ep(mac: &str) -> PowerShelfEndpoint {
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

    async fn load_maintenance_scope(pool: &PgPool, rack_id: &RackId) -> Option<MaintenanceScope> {
        let mut conn = pool.acquire().await.unwrap();
        let rack = db::rack::find_by(
            &mut *conn,
            db::ObjectColumnFilter::One(db::rack::IdColumn, rack_id),
        )
        .await
        .expect("find rack")
        .pop()
        .expect("rack exists");
        rack.config.maintenance_requested
    }

    async fn load_power_shelf_maintenance_request(
        pool: &PgPool,
        power_shelf_id: &PowerShelfId,
    ) -> Option<PowerShelfMaintenanceRequest> {
        let mut conn = pool.acquire().await.unwrap();
        let shelf = db::power_shelf::find_by(
            &mut conn,
            db::ObjectColumnFilter::One(db::power_shelf::IdColumn, power_shelf_id),
        )
        .await
        .expect("find power shelf")
        .pop()
        .expect("power shelf exists");
        shelf.power_shelf_maintenance_requested
    }

    #[carbide_macros::sqlx_test]
    async fn power_control_writes_per_shelf_maintenance(pool: PgPool) {
        let (rack_id, ps1, ps2, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct.clone());

        let eps = vec![make_ep(PS_MAC_1), make_ep(PS_MAC_2)];
        let results = wrapper
            .power_control(&eps, PowerAction::GracefulShutdown)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));

        for ps_id in [ps1, ps2] {
            let req = load_power_shelf_maintenance_request(&pool, &ps_id)
                .await
                .unwrap_or_else(|| panic!("expected per-shelf maintenance request for {ps_id}"));
            assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOff);
            assert_eq!(req.initiator, COMPONENT_MANAGER_INITIATOR);
        }

        assert!(
            load_maintenance_scope(&pool, &rack_id).await.is_none(),
            "power_control must not write a rack-level MaintenanceScope"
        );
        assert_eq!(*direct.power_control_calls.lock().unwrap(), 0);
    }

    #[carbide_macros::sqlx_test]
    async fn power_control_on_maps_to_power_on(pool: PgPool) {
        let (_rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        let req = load_power_shelf_maintenance_request(&pool, &ps1)
            .await
            .expect("per-shelf maintenance request");
        assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOn);
    }

    #[carbide_macros::sqlx_test]
    async fn power_control_force_off_maps_to_power_off(pool: PgPool) {
        let (_rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        wrapper
            .power_control(&eps, PowerAction::ForceOff)
            .await
            .unwrap();

        let req = load_power_shelf_maintenance_request(&pool, &ps1)
            .await
            .expect("per-shelf maintenance request");
        assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOff);
    }

    #[carbide_macros::sqlx_test]
    async fn power_control_unsupported_action_is_rejected(pool: PgPool) {
        let (_rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        for unsupported in [
            PowerAction::GracefulRestart,
            PowerAction::ForceRestart,
            PowerAction::AcPowercycle,
        ] {
            let err = wrapper.power_control(&eps, unsupported).await.unwrap_err();
            match err {
                ComponentManagerError::InvalidArgument(msg) => {
                    assert!(
                        msg.contains("not supported"),
                        "unexpected error message: {msg}"
                    );
                }
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
        }

        assert!(
            load_power_shelf_maintenance_request(&pool, &ps1)
                .await
                .is_none(),
            "no per-shelf maintenance request should have been written for unsupported actions",
        );
    }

    #[carbide_macros::sqlx_test]
    async fn update_firmware_writes_maintenance_scope(pool: PgPool) {
        let (rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct.clone());

        let eps = vec![make_ep(PS_MAC_1)];
        let results = wrapper
            .update_firmware(&eps, "fw-2.0.0", &[PowerShelfComponent::Pmc])
            .await
            .unwrap();

        assert!(results[0].success);

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        assert_eq!(scope.power_shelf_ids, vec![ps1]);
        match &scope.activities[0] {
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version, ..
            } => {
                assert_eq!(firmware_version.as_deref(), Some("fw-2.0.0"));
            }
            other => panic!("expected FirmwareUpgrade activity, got {other:?}"),
        }
        assert_eq!(*direct.update_firmware_calls.lock().unwrap(), 0);
    }

    #[carbide_macros::sqlx_test]
    async fn update_firmware_empty_version_becomes_none(pool: PgPool) {
        let (rack_id, _, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        wrapper.update_firmware(&eps, "", &[]).await.unwrap();

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        match &scope.activities[0] {
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version, ..
            } => {
                assert!(firmware_version.is_none());
            }
            other => panic!("expected FirmwareUpgrade activity, got {other:?}"),
        }
    }

    #[carbide_macros::sqlx_test]
    async fn partial_unknown_mac_known_still_written(pool: PgPool) {
        let (rack_id, _, ps2, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(UNKNOWN_MAC), make_ep(PS_MAC_2)];
        let results = wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        assert!(!results[0].success);
        assert!(
            results[0]
                .error
                .as_deref()
                .unwrap()
                .contains("no power shelf")
        );
        assert!(results[1].success);

        let req = load_power_shelf_maintenance_request(&pool, &ps2)
            .await
            .expect("per-shelf maintenance request for ps2");
        assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOn);
        assert!(
            load_maintenance_scope(&pool, &rack_id).await.is_none(),
            "power_control must not write a rack-level MaintenanceScope"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn all_unknown_macs_nothing_written(pool: PgPool) {
        let (rack_id, ps1, ps2, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(UNKNOWN_MAC)];
        let results = wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        assert!(!results[0].success);
        for ps_id in [ps1, ps2] {
            assert!(
                load_power_shelf_maintenance_request(&pool, &ps_id)
                    .await
                    .is_none(),
                "no per-shelf maintenance request expected for {ps_id}"
            );
        }
        assert!(load_maintenance_scope(&pool, &rack_id).await.is_none());
    }

    /// `power_control` is not gated on the rack's maintenance state because
    /// it routes through the per-shelf state controller, not the rack-level
    /// `MaintenanceScope`. A rack stuck in firmware-upgrade maintenance must
    /// not block a power-on/power-off request to one of its shelves.
    #[carbide_macros::sqlx_test]
    async fn power_control_ignores_rack_maintenance_state(pool: PgPool) {
        let (rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        set_rack_state(
            &pool,
            &rack_id,
            model::rack::RackState::Maintenance {
                maintenance_state: RackMaintenanceState::FirmwareUpgrade {
                    rack_firmware_upgrade: FirmwareUpgradeState::Start,
                },
            },
        )
        .await;

        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        let results = wrapper.power_control(&eps, PowerAction::On).await.unwrap();
        assert!(results[0].success);

        let req = load_power_shelf_maintenance_request(&pool, &ps1)
            .await
            .expect("per-shelf maintenance request");
        assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOn);
    }

    /// A second `power_control` call overwrites the first per-shelf
    /// maintenance request (mirrors the behaviour of the existing
    /// `set_power_shelf_maintenance` API handler so operators can flip
    /// On -> Off before the controller has acted on either request).
    #[carbide_macros::sqlx_test]
    async fn power_control_overwrites_pending_request(pool: PgPool) {
        let (_rack_id, ps1, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool.clone(), direct);

        let eps = vec![make_ep(PS_MAC_1)];
        wrapper.power_control(&eps, PowerAction::On).await.unwrap();
        wrapper
            .power_control(&eps, PowerAction::ForceOff)
            .await
            .unwrap();

        let req = load_power_shelf_maintenance_request(&pool, &ps1)
            .await
            .expect("per-shelf maintenance request");
        assert_eq!(req.operation, PowerShelfMaintenanceOperation::PowerOff);
    }

    #[carbide_macros::sqlx_test]
    async fn get_firmware_status_passes_through(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool, direct.clone());

        let eps = vec![make_ep(PS_MAC_1)];
        let statuses = wrapper.get_firmware_status(&eps).await.unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(*direct.get_firmware_status_calls.lock().unwrap(), 1);
    }

    #[carbide_macros::sqlx_test]
    async fn list_firmware_passes_through(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool, direct.clone());

        let eps = vec![make_ep(PS_MAC_1)];
        let versions = wrapper.list_firmware(&eps).await.unwrap();

        assert_eq!(versions[0].versions, vec!["1.0"]);
        assert_eq!(*direct.list_firmware_calls.lock().unwrap(), 1);
    }

    #[carbide_macros::sqlx_test]
    async fn direct_field_exposes_underlying_backend(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerPowerShelf::new(pool, direct);

        assert_eq!(wrapper.direct.name(), "recording");
    }
}
