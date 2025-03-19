use std::collections::HashMap;
use std::ops::DerefMut;

use sqlx::{Acquire, FromRow, Postgres, Transaction};

use crate::{
    CarbideError,
    cfg::file::CarbideConfig,
    db::{self, DatabaseError, machine::MachineSearchConfig, managed_host::LoadSnapshotOptions},
    machine_update_manager::machine_update_module::{
        AutomaticFirmwareUpdateReference, DpuReprovisionInitiator,
        create_host_update_health_report, machine_updates_in_progress,
    },
    model::machine::{ManagedHostState, ManagedHostStateSnapshot, ReprovisionRequest},
};
use forge_uuid::machine::MachineId;

#[derive(FromRow, Debug)]
pub struct DpuMachineUpdate {
    pub host_machine_id: MachineId,
    pub dpu_machine_id: MachineId,
    pub firmware_version: String,
    pub product_name: String,
}

impl DpuMachineUpdate {
    /// Find DPUs and the corresponding host that needs to have its firmware updated.
    /// DPUs can be updated when:
    /// 1. the installed firmware does not match the expected firmware
    /// 2. the DPU is not marked for reprovisioning
    /// 3. the DPU is not marked for maintenance.
    /// 4. the Host is healthy (no pending health alert)
    /// 5. If all DPUs need upgrade, put all in queue. State machine supports upgrading multiple
    ///    DPUs of a managedhost.
    /// 6. If some of the DPUs for a managed host need upgrade, put them in queue.
    ///     6.1. Make sure none of the DPU is under reprovisioning while queuing a new DPU for a
    ///       managedhost. This is done by confirming that Host is not marked for updates
    ///
    pub async fn find_available_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_versions: &HashMap<String, String>,
        limit: Option<i32>,
        config: &CarbideConfig,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        if limit.is_some_and(|l| l <= 0) {
            return Ok(vec![]);
        }

        let outdated_dpus =
            Self::find_outdated_dpus(txn, expected_firmware_versions, config).await?;

        let mut scheduled_host_updates = 0;
        let available_outdated_dpus: Vec<DpuMachineUpdate> = outdated_dpus
            .into_iter()
            .filter_map(|outdated_host| {
                // If the limit on scheduled host updates is reached, skip creating more
                if let Some(limit) = limit {
                    if scheduled_host_updates >= limit {
                        return None;
                    }
                }
                if !outdated_host.is_available_for_updates() {
                    return None;
                }
                scheduled_host_updates += 1;
                Some(outdated_host.outdated_dpus)
            })
            .flatten()
            .collect();

        Ok(available_outdated_dpus)
    }

    pub async fn find_unavailable_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_versions: &HashMap<String, String>,
        config: &CarbideConfig,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let outdated_dpus =
            Self::find_outdated_dpus(txn, expected_firmware_versions, config).await?;

        let unavailable_outdated_dpus: Vec<DpuMachineUpdate> = outdated_dpus
            .into_iter()
            .filter_map(|outdated_host| {
                if outdated_host.is_available_for_updates() {
                    return None;
                }
                Some(outdated_host.outdated_dpus)
            })
            .flatten()
            .collect();

        Ok(unavailable_outdated_dpus)
    }

    pub async fn find_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_versions: &HashMap<String, String>,
        config: &CarbideConfig,
    ) -> Result<Vec<OutdatedHost>, DatabaseError> {
        if expected_firmware_versions.is_empty() {
            return Err(DatabaseError::new(
                file!(),
                line!(),
                "find_outdated_dpus",
                sqlx::Error::Configuration(Box::new(CarbideError::InvalidArgument(
                    "Missing expected_firmware_versions".to_string(),
                ))),
            ));
        }

        let machine_ids = db::machine::find_machine_ids(
            txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;
        let snapshots = db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: config.host_health,
            },
        )
        .await?;

        let outdated_hosts: Vec<OutdatedHost> = snapshots
            .into_iter()
            .filter_map(|(machine_id, managed_host)| {
                let outdated_dpus: Vec<DpuMachineUpdate> = managed_host
                    .dpu_snapshots
                    .iter()
                    .filter_map(|dpu| {
                        let firmware_version = dpu
                            .hardware_info
                            .as_ref()
                            .and_then(|info| info.dpu_info.as_ref())
                            .map(|dpu_info| dpu_info.firmware_version.clone())
                            .unwrap_or_default();
                        let product_name = dpu
                            .hardware_info
                            .as_ref()
                            .and_then(|info| info.dmi_data.as_ref())
                            .map(|dmi_data| dmi_data.product_name.clone())
                            .unwrap_or_default();

                        let is_outdated = match expected_firmware_versions.get(&product_name) {
                            Some(expected_version) => expected_version != &firmware_version,
                            None => false,
                        };
                        if !is_outdated {
                            return None;
                        }

                        Some(DpuMachineUpdate {
                            host_machine_id: machine_id,
                            dpu_machine_id: dpu.id,
                            firmware_version,
                            product_name,
                        })
                    })
                    .collect();

                if outdated_dpus.is_empty() {
                    return None;
                }

                Some(OutdatedHost {
                    managed_host,
                    outdated_dpus,
                })
            })
            .collect();

        Ok(outdated_hosts)
    }

    pub async fn get_fw_updates_running_count(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<i64, DatabaseError> {
        let query = r#"SELECT COUNT(*) as count FROM machines m
            WHERE (reprovisioning_requested->>'update_firmware')::boolean is true  
            AND reprovisioning_requested->>'started_at' IS NOT NULL;"#;
        let (count,): (i64,) = sqlx::query_as(query)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_available_outdated_dpus", e))?;

        Ok(count)
    }

    pub async fn trigger_reprovisioning_for_managed_host(
        txn: &mut Transaction<'_, Postgres>,
        host_machine_id: &MachineId,
        machine_updates: &[DpuMachineUpdate],
        expected_versions: &HashMap<String, String>,
    ) -> Result<(), CarbideError> {
        let mut inner_txn = txn.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin trigger_reprovisioning_for_managed_host",
                e,
            ))
        })?;

        let mut host_expected_version = None;
        for machine_update in machine_updates {
            let expected_version = expected_versions
                .get(&machine_update.product_name)
                .ok_or_else(|| {
                    DatabaseError::new(
                        file!(),
                        line!(),
                        "",
                        sqlx::Error::ColumnNotFound("product_name missing".to_owned()),
                    )
                })?;

            if host_expected_version.is_none() {
                host_expected_version = Some(expected_version.clone());
            }

            let initiator = DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
                from: machine_update.firmware_version.clone(),
                to: expected_version.clone(),
            });

            let reprovision_time = chrono::Utc::now();
            let req = ReprovisionRequest {
                requested_at: reprovision_time,
                initiator: initiator.to_string(),
                update_firmware: true,
                started_at: None,
                user_approval_received: false,
                restart_reprovision_requested_at: reprovision_time,
            };

            let query = r#"UPDATE machines SET reprovisioning_requested=$1 WHERE controller_state = '{"state": "ready"}' AND id=$2 RETURNING id"#;
            sqlx::query(query)
                .bind(sqlx::types::Json(req))
                .bind(machine_update.dpu_machine_id.to_string())
                .fetch_one(inner_txn.deref_mut())
                .await
                .map_err(|err: sqlx::Error| match err {
                    sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                        kind: "trigger_reprovisioning_for_managed_host",
                        id: machine_update.dpu_machine_id.to_string(),
                    },
                    _ => DatabaseError::new(file!(), line!(), query, err).into(),
                })?;
        }

        let initiator_host = DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
            // In case of multidpu, DPUs can have different versions.
            from: "".to_string(),
            to: host_expected_version.unwrap_or("".to_string()),
        });

        let health_override = create_host_update_health_report(
            Some("DpuFirmware".to_string()),
            initiator_host.to_string(),
        );

        // Mark the Host as in update.
        // If an update is already scheduled (host-update field is set),
        // then the process is aborted
        let query = r#"UPDATE machines SET health_report_overrides = jsonb_set(
                coalesce(health_report_overrides, '{"merges": {}}'::jsonb),
                '{merges,host-update}',
                $1::jsonb
            )
            WHERE controller_state = '{"state": "ready"}' AND id=$2
            AND coalesce(health_report_overrides, '{"merges": {}}'::jsonb)->'merges' ? 'host-update' = FALSE
            RETURNING id"#;
        sqlx::query(query)
            .bind(sqlx::types::Json(&health_override))
            .bind(host_machine_id.to_string())
            .fetch_one(inner_txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::RowNotFound => CarbideError::NotFoundError {
                    kind: "trigger_reprovisioning_for_managed_host",
                    id: host_machine_id.to_string(),
                },
                _ => DatabaseError::new(file!(), line!(), query, err).into(),
            })?;

        inner_txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit trigger_reprovisioning_for_managed_host",
                e,
            ))
        })?;

        Ok(())
    }

    pub async fn get_reprovisioning_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let reference = AutomaticFirmwareUpdateReference::REF_NAME.to_string() + "%";

        let query = r#"SELECT mi.machine_id AS host_machine_id, m.id AS dpu_machine_id, '' AS firmware_version, '' AS product_name
            FROM machines m
            INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
            WHERE m.reprovisioning_requested->>'initiator' like $1
            AND mi.attached_dpu_machine_id != mi.machine_id;"#;

        let result: Vec<DpuMachineUpdate> = sqlx::query_as(query)
            .bind(&reference)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result)
    }

    pub async fn get_updated_machines(
        txn: &mut Transaction<'_, Postgres>,
        config: &CarbideConfig,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let machine_ids = db::machine::find_machine_ids(
            txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;
        let snapshots = db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: config.host_health,
            },
        )
        .await?;

        let updated_machines: Vec<DpuMachineUpdate> = snapshots
            .into_iter()
            .filter_map(|(machine_id, managed_host)| {
                // Skip looking at any machines that are not marked for updates
                if !machine_updates_in_progress(&managed_host.host_snapshot) {
                    return None;
                }
                // Skip any machines that are not done updating
                if !matches!(managed_host.managed_state, ManagedHostState::Ready) {
                    return None;
                }
                // Check if all DPUs have the `reprovisioning_requested` flag cleared
                if managed_host
                    .dpu_snapshots
                    .iter()
                    .any(|dpu| dpu.reprovision_requested.is_some())
                {
                    return None;
                }

                // We only signal an update as complete once ALL DPUs are done
                // That prevents removing the updating flags from the Host
                // if just one DPU completes the update
                let completed_updates: Vec<DpuMachineUpdate> = managed_host
                    .dpu_snapshots
                    .iter()
                    .map(|dpu| DpuMachineUpdate {
                        host_machine_id: machine_id,
                        dpu_machine_id: dpu.id,
                        firmware_version: dpu
                            .hardware_info
                            .as_ref()
                            .and_then(|info| info.dpu_info.as_ref())
                            .map(|dpu_info| dpu_info.firmware_version.clone())
                            .unwrap_or_default(),
                        product_name: dpu
                            .hardware_info
                            .as_ref()
                            .and_then(|info| info.dmi_data.as_ref())
                            .map(|dmi_data| dmi_data.product_name.clone())
                            .unwrap_or_default(),
                    })
                    .collect();

                Some(completed_updates)
            })
            .flatten()
            .collect();

        Ok(updated_machines)
    }
}

pub struct OutdatedHost {
    pub managed_host: ManagedHostStateSnapshot,
    pub outdated_dpus: Vec<DpuMachineUpdate>,
}

impl OutdatedHost {
    pub fn is_available_for_updates(&self) -> bool {
        // Skip any machines that have pending health alerts
        if !self.managed_host.aggregate_health.alerts.is_empty() {
            return false;
        }
        // Skip looking at any machines that are marked for updates
        if machine_updates_in_progress(&self.managed_host.host_snapshot) {
            return false;
        }
        // Skip any machines that are not Ready
        if !matches!(self.managed_host.managed_state, ManagedHostState::Ready) {
            return false;
        }

        // Check if all DPUs have the `reprovisioning_requested` flag cleared
        if self
            .managed_host
            .dpu_snapshots
            .iter()
            .any(|dpu| dpu.reprovision_requested.is_some())
        {
            return false;
        }

        true
    }
}
