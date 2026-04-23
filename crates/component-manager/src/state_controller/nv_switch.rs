// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A Component Manager `NvSwitchManager` implementation that routes write
//! operations to the rack state controller (by writing a `MaintenanceScope`
//! onto `racks.config.maintenance_requested`) and passes reads through to
//! the wrapped direct backend.

use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::ObjectColumnFilter;
use mac_address::MacAddress;
use model::component_manager::{NvSwitchComponent, PowerAction};
use model::rack::{MaintenanceActivity, MaintenanceScope};
use sqlx::PgPool;
use tracing::instrument;

use super::unique_rack_id;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    NvSwitchManager, SwitchComponentResult, SwitchEndpoint, SwitchFirmwareUpdateStatus,
};

const UNKNOWN_MAC_ERROR: &str = "no switch row found for this BMC MAC address";
const DEVICE_KIND: &str = "switches";

/// Wraps a direct `NvSwitchManager` backend (e.g., `RmsBackend`, `NsmBackend`)
/// and routes state-changing operations through the rack state controller
/// instead of dispatching them directly.
///
/// `direct` is deliberately public so the rack state controller can reach
/// through to it for the real dispatch.
pub struct StateControllerNvSwitch {
    db: PgPool,
    pub direct: Arc<dyn NvSwitchManager>,
}

impl std::fmt::Debug for StateControllerNvSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateControllerNvSwitch")
            .field("direct", &self.direct.name())
            .finish()
    }
}

impl StateControllerNvSwitch {
    pub fn new(db: PgPool, direct: Arc<dyn NvSwitchManager>) -> Self {
        Self { db, direct }
    }

    /// Resolve endpoints, preflight, write a `MaintenanceScope` to the rack,
    /// and return the per-endpoint result vector. Shared by `power_control`
    /// and `queue_firmware_updates`.
    async fn write_scope(
        &self,
        endpoints: &[SwitchEndpoint],
        activity: MaintenanceActivity,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let macs: Vec<MacAddress> = endpoints.iter().map(|ep| ep.bmc_mac).collect();
        let resolved = db::switch::find_ids_by_bmc_macs(&self.db, &macs)
            .await
            .map_err(|e| {
                ComponentManagerError::Internal(format!("failed to resolve switch IDs by MAC: {e}"))
            })?;

        let id_by_mac: HashMap<MacAddress, (SwitchId, Option<RackId>)> = resolved
            .into_iter()
            .map(|r| (r.bmc_mac_address, (r.id, r.rack_id)))
            .collect();

        if id_by_mac.is_empty() {
            return Ok(endpoints
                .iter()
                .map(|ep| unknown_mac_result(ep.bmc_mac))
                .collect());
        }

        let rack_id = unique_rack_id(
            endpoints
                .iter()
                .filter_map(|ep| id_by_mac.get(&ep.bmc_mac).map(|(_, rack)| rack.as_ref())),
            DEVICE_KIND,
        )?;

        let switch_ids: Vec<SwitchId> = endpoints
            .iter()
            .filter_map(|ep| id_by_mac.get(&ep.bmc_mac).map(|(id, _)| *id))
            .collect();

        self.persist_scope(&rack_id, switch_ids, activity).await?;

        Ok(endpoints
            .iter()
            .map(|ep| {
                if id_by_mac.contains_key(&ep.bmc_mac) {
                    SwitchComponentResult {
                        bmc_mac: ep.bmc_mac,
                        success: true,
                        error: None,
                    }
                } else {
                    unknown_mac_result(ep.bmc_mac)
                }
            })
            .collect())
    }

    async fn persist_scope(
        &self,
        rack_id: &RackId,
        switch_ids: Vec<SwitchId>,
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
            switch_ids,
            power_shelf_ids: vec![],
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
impl NvSwitchManager for StateControllerNvSwitch {
    fn name(&self) -> &str {
        "state-controller"
    }

    #[instrument(skip(self), fields(backend = "state-controller"))]
    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        self.write_scope(endpoints, MaintenanceActivity::PowerControl { action })
            .await
    }

    #[instrument(skip(self), fields(backend = "state-controller"))]
    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        _components: &[NvSwitchComponent],
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
        let firmware_version = if bundle_version.is_empty() {
            None
        } else {
            Some(bundle_version.to_owned())
        };
        self.write_scope(
            endpoints,
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version,
                components: vec![],
            },
        )
        .await
    }

    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
        self.direct.get_firmware_status(endpoints).await
    }

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
        self.direct.list_firmware_bundles().await
    }
}

fn unknown_mac_result(bmc_mac: MacAddress) -> SwitchComponentResult {
    SwitchComponentResult {
        bmc_mac,
        success: false,
        error: Some(UNKNOWN_MAC_ERROR.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use model::rack::{FirmwareUpgradeState, RackMaintenanceState};

    use super::*;
    use crate::test_support::{SW_MAC_1, SW_MAC_2, UNKNOWN_MAC, seed_test_data, set_rack_state};

    #[derive(Debug, Default)]
    struct RecordingDirect {
        power_control_calls: Mutex<usize>,
        queue_firmware_updates_calls: Mutex<usize>,
        get_firmware_status_calls: Mutex<usize>,
        list_firmware_bundles_calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl NvSwitchManager for RecordingDirect {
        fn name(&self) -> &str {
            "recording"
        }

        async fn power_control(
            &self,
            _endpoints: &[SwitchEndpoint],
            _action: PowerAction,
        ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
            *self.power_control_calls.lock().unwrap() += 1;
            Ok(vec![])
        }

        async fn queue_firmware_updates(
            &self,
            _endpoints: &[SwitchEndpoint],
            _bundle_version: &str,
            _components: &[NvSwitchComponent],
        ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError> {
            *self.queue_firmware_updates_calls.lock().unwrap() += 1;
            Ok(vec![])
        }

        async fn get_firmware_status(
            &self,
            endpoints: &[SwitchEndpoint],
        ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError> {
            *self.get_firmware_status_calls.lock().unwrap() += 1;
            Ok(endpoints
                .iter()
                .map(|ep| SwitchFirmwareUpdateStatus {
                    bmc_mac: ep.bmc_mac,
                    state: model::component_manager::FirmwareState::Unknown,
                    target_version: String::new(),
                    error: None,
                })
                .collect())
        }

        async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError> {
            *self.list_firmware_bundles_calls.lock().unwrap() += 1;
            Ok(vec!["fw-1.0".into()])
        }
    }

    fn make_ep(mac: &str) -> SwitchEndpoint {
        SwitchEndpoint {
            bmc_ip: "10.0.0.1".parse().unwrap(),
            bmc_mac: mac.parse().unwrap(),
            nvos_ip: "10.0.0.2".parse().unwrap(),
            nvos_mac: "11:22:33:44:55:66".parse().unwrap(),
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

    #[carbide_macros::sqlx_test]
    async fn power_control_writes_maintenance_scope(pool: PgPool) {
        let (rack_id, _, _, sw1, sw2) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct.clone());

        let eps = vec![make_ep(SW_MAC_1), make_ep(SW_MAC_2)];
        let results = wrapper
            .power_control(&eps, PowerAction::AcPowercycle)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        assert!(scope.machine_ids.is_empty());
        assert!(scope.power_shelf_ids.is_empty());
        assert_eq!(scope.switch_ids, vec![sw1, sw2]);
        match &scope.activities[0] {
            MaintenanceActivity::PowerControl { action } => {
                assert_eq!(*action, PowerAction::AcPowercycle);
            }
            other => panic!("expected PowerControl activity, got {other:?}"),
        }
        assert_eq!(*direct.power_control_calls.lock().unwrap(), 0);
    }

    #[carbide_macros::sqlx_test]
    async fn queue_firmware_updates_writes_maintenance_scope(pool: PgPool) {
        let (rack_id, _, _, sw1, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct.clone());

        let eps = vec![make_ep(SW_MAC_1)];
        let results = wrapper
            .queue_firmware_updates(&eps, "nvos-3.0", &[NvSwitchComponent::Bmc])
            .await
            .unwrap();

        assert!(results[0].success);

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        assert_eq!(scope.switch_ids, vec![sw1]);
        match &scope.activities[0] {
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version, ..
            } => {
                assert_eq!(firmware_version.as_deref(), Some("nvos-3.0"));
            }
            other => panic!("expected FirmwareUpgrade activity, got {other:?}"),
        }
        assert_eq!(*direct.queue_firmware_updates_calls.lock().unwrap(), 0);
    }

    #[carbide_macros::sqlx_test]
    async fn partial_unknown_mac_known_still_written(pool: PgPool) {
        let (rack_id, _, _, _, sw2) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct);

        let eps = vec![make_ep(UNKNOWN_MAC), make_ep(SW_MAC_2)];
        let results = wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        assert!(!results[0].success);
        assert!(results[0].error.as_deref().unwrap().contains("no switch"));
        assert!(results[1].success);

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        assert_eq!(scope.switch_ids, vec![sw2]);
    }

    #[carbide_macros::sqlx_test]
    async fn all_unknown_macs_no_scope_written(pool: PgPool) {
        let (rack_id, _, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct);

        let eps = vec![make_ep(UNKNOWN_MAC)];
        let results = wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        assert!(!results[0].success);
        assert!(load_maintenance_scope(&pool, &rack_id).await.is_none());
    }

    #[carbide_macros::sqlx_test]
    async fn rack_not_ready_or_error_is_rejected(pool: PgPool) {
        let (rack_id, _, _, _, _) = seed_test_data(&pool).await;
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
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct);

        let eps = vec![make_ep(SW_MAC_1)];
        let err = wrapper
            .power_control(&eps, PowerAction::On)
            .await
            .unwrap_err();
        match err {
            ComponentManagerError::InvalidArgument(msg) => {
                assert!(msg.contains("Ready or Error"), "unexpected: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[carbide_macros::sqlx_test]
    async fn maintenance_already_pending_is_rejected(pool: PgPool) {
        let (rack_id, _, _, _, _) = seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool.clone(), direct);

        let eps = vec![make_ep(SW_MAC_1)];
        wrapper.power_control(&eps, PowerAction::On).await.unwrap();

        let err = wrapper
            .power_control(&eps, PowerAction::ForceOff)
            .await
            .unwrap_err();
        match err {
            ComponentManagerError::InvalidArgument(msg) => {
                assert!(msg.contains("already has a pending"), "unexpected: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        let scope = load_maintenance_scope(&pool, &rack_id)
            .await
            .expect("scope");
        match &scope.activities[0] {
            MaintenanceActivity::PowerControl { action } => {
                assert_eq!(*action, PowerAction::On);
            }
            other => panic!("expected PowerControl::On, got {other:?}"),
        }
    }

    #[carbide_macros::sqlx_test]
    async fn get_firmware_status_passes_through(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool, direct.clone());

        let eps = vec![make_ep(SW_MAC_1)];
        let statuses = wrapper.get_firmware_status(&eps).await.unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(*direct.get_firmware_status_calls.lock().unwrap(), 1);
    }

    #[carbide_macros::sqlx_test]
    async fn list_firmware_bundles_passes_through(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool, direct.clone());

        let bundles = wrapper.list_firmware_bundles().await.unwrap();

        assert_eq!(bundles, vec!["fw-1.0".to_string()]);
        assert_eq!(*direct.list_firmware_bundles_calls.lock().unwrap(), 1);
    }

    #[carbide_macros::sqlx_test]
    async fn direct_field_exposes_underlying_backend(pool: PgPool) {
        seed_test_data(&pool).await;
        let direct = Arc::new(RecordingDirect::default());
        let wrapper = StateControllerNvSwitch::new(pool, direct);

        assert_eq!(wrapper.direct.name(), "recording");
    }
}
