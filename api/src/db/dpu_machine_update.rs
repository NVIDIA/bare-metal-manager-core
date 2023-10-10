use sqlx::{FromRow, Postgres, Transaction};

use crate::{
    machine_update_manager::machine_update_module::{
        AutomaticFirmwareUpdateReference, MaintenanceReference,
    },
    model::machine::{machine_id::MachineId, ReprovisionRequest},
};

use super::{machine::DbMachineId, DatabaseError};

#[derive(FromRow)]
pub struct DbDpuMachineUpdate {
    pub host_machine_id: DbMachineId,
    pub dpu_machine_id: DbMachineId,
    pub firmware_version: String,
}

pub struct DpuMachineUpdate {
    pub host_machine_id: MachineId,
    pub dpu_machine_id: MachineId,
    pub firmware_version: String,
}

impl From<DbDpuMachineUpdate> for DpuMachineUpdate {
    fn from(value: DbDpuMachineUpdate) -> Self {
        DpuMachineUpdate {
            host_machine_id: value.host_machine_id.into(),
            dpu_machine_id: value.dpu_machine_id.into(),
            firmware_version: value.firmware_version,
        }
    }
}

impl DpuMachineUpdate {
    /// Find DPUs and the corresponding host that needs to have its firmware updated.
    /// DPUs can be updated when:
    /// 1. the managed host is in the ready state.
    /// 2. the installed firmware does not match the expected firmware
    /// 3. the DPU is not marked for reprovisioning
    /// 4. the DPU is not marked for maintenance.
    ///
    pub async fn find_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_version: &str,
        limit: i32,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        if limit <= 0 {
            return Ok(vec![]);
        }

        let query = r#"SELECT mi.machine_id as host_machine_id, m.id as dpu_machine_id, 
            mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version 
            FROM machines m
            INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
            INNER JOIN machine_topologies mt ON m.id = mt.machine_id
            WHERE m.reprovisioning_requested IS NULL 
            AND mi.machine_id != mi.attached_dpu_machine_id 
            AND m.controller_state = '{"state": "ready"}' 
            AND m.maintenance_start_time IS NULL 
            AND mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' != $1 LIMIT $2;"#;
        let result = sqlx::query_as::<_, DbDpuMachineUpdate>(query)
            .bind(expected_firmware_version)
            .bind(limit)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result.into_iter().map(DbDpuMachineUpdate::into).collect())
    }

    pub async fn trigger_reprovisioning_for_managed_host(
        txn: &mut Transaction<'_, Postgres>,
        machine_update: &DpuMachineUpdate,
        expected_version: String,
    ) -> Result<Vec<MachineId>, DatabaseError> {
        let initiator = MaintenanceReference::Automatic(AutomaticFirmwareUpdateReference {
            from: machine_update.firmware_version.clone(),
            to: expected_version,
        });
        let req = ReprovisionRequest {
            requested_at: chrono::Utc::now(),
            initiator: initiator.to_string(),
            update_firmware: true,
        };

        let machine_ids = vec![
            machine_update.host_machine_id.to_string(),
            machine_update.dpu_machine_id.to_string(),
        ];

        let query = r#"UPDATE machines SET reprovisioning_requested=$1, maintenance_reference=$2, maintenance_start_time=NOW() WHERE controller_state = '{"state": "ready"}' AND id=ANY($3) RETURNING id;"#;
        let ids = sqlx::query_as::<_, DbMachineId>(query)
            .bind(sqlx::types::Json(req))
            .bind(initiator.to_string())
            .bind(machine_ids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(ids.into_iter().map(MachineId::from).collect())
    }

    pub async fn get_reprovisioning_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        // use `maintenance_reference` as the reprovisioning fields are cleared by the state machine at the start of reprovisioning
        let query = r#"SELECT mi.machine_id AS host_machine_id, m.id AS dpu_machine_id, '' AS firmware_version
            FROM machines m
            INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id 
            WHERE m.maintenance_reference like 'Automatic dpu firmware update from%'
            AND mi.attached_dpu_machine_id != mi.machine_id;"#;

        let result: Vec<DbDpuMachineUpdate> = sqlx::query_as::<_, DbDpuMachineUpdate>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result.into_iter().map(DpuMachineUpdate::from).collect())
    }

    pub async fn get_updated_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let query = r#"SELECT mi.machine_id as host_machine_id, mi.attached_dpu_machine_id as dpu_machine_id, 
        mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version 
        FROM machines m
        INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
        INNER JOIN machine_topologies mt ON m.id = mt.machine_id 
        WHERE mi.machine_id != mi.attached_dpu_machine_id 
        AND m.controller_state = '{"state": "ready"}' 
        AND m.maintenance_reference like 'Automatic dpu firmware update from%'
        AND m.reprovisioning_requested IS NULL"#;

        let updated_machines: Vec<DbDpuMachineUpdate> =
            sqlx::query_as::<_, DbDpuMachineUpdate>(query)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(updated_machines
            .into_iter()
            .map(DpuMachineUpdate::from)
            .collect())
    }
}
