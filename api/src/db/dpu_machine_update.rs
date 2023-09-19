use std::str::FromStr;

use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::model::machine::machine_id::MachineId;

use super::DatabaseError;

pub struct DpuMachineUpdate {
    pub host_machine_id: MachineId,
    pub dpu_machine_id: MachineId,
    pub firmware_version: String,
}

impl<'r> FromRow<'r, PgRow> for DpuMachineUpdate {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DpuMachineUpdate {
            host_machine_id: MachineId::from_str(row.try_get("host_machine_id")?).map_err(|e| {
                sqlx::Error::ColumnDecode {
                    index: "host_machine_id".to_owned(),
                    source: Box::new(e),
                }
            })?,
            dpu_machine_id: MachineId::from_str(row.try_get("dpu_machine_id")?).map_err(|e| {
                sqlx::Error::ColumnDecode {
                    index: "dpu_machine_id".to_owned(),
                    source: Box::new(e),
                }
            })?,
            firmware_version: row.try_get("firmware_version")?,
        })
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
        let result = sqlx::query_as::<_, DpuMachineUpdate>(query)
            .bind(expected_firmware_version)
            .bind(limit)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result)
    }

    pub async fn get_reprovisioning_count(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<i32, DatabaseError> {
        let query = r#"SELECT COUNT(reprovisioning_requested)::int FROM machines;"#;
        let result = sqlx::query::<_>(query)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let count = result
            .try_get("count")
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(count)
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

        let updated_machines: Vec<DpuMachineUpdate> = sqlx::query_as::<_, DpuMachineUpdate>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(updated_machines)
    }
}
