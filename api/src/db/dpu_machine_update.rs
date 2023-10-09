use sqlx::{FromRow, Postgres, Transaction};

use crate::model::machine::machine_id::MachineId;

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

        let query = r#"SELECT mi.machine_id as host_machine_id, mi.attached_dpu_machine_id as dpu_machine_id, 
            mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version 
            FROM machines m, machine_interfaces mi, machine_topologies mt 
            WHERE m.id = mi.attached_dpu_machine_id 
            AND mi.attached_dpu_machine_id = mt.machine_id 
            AND m.reprovisioning_requested IS NULL 
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

    pub async fn get_reprovisioning_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<MachineId>, DatabaseError> {
        // use `maintenance_reference` as the reprovisioning fields are cleared by the state machine at the start of reprovisioning
        let query = r#"SELECT m.id FROM machines m, machine_interfaces mi WHERE m.id = mi.attached_dpu_machine_id 
        AND m.maintenance_reference like 'Automatic dpu firmware update from%'
        AND mi.attached_dpu_machine_id != mi.machine_id;"#;

        let result: Vec<DbMachineId> = sqlx::query_as(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result.into_iter().map(MachineId::from).collect())
    }

    pub async fn get_updated_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let query = r#"SELECT mi.machine_id as host_machine_id, mi.attached_dpu_machine_id as dpu_machine_id, 
        mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version 
        FROM machines m, machine_interfaces mi, machine_topologies mt 
        WHERE m.id = mi.attached_dpu_machine_id 
        AND mi.attached_dpu_machine_id = mt.machine_id 
        AND mi.machine_id != mi.attached_dpu_machine_id 
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
