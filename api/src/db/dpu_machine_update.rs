use std::collections::HashMap;

use sqlx::{FromRow, Postgres, Transaction};

use crate::{
    machine_update_manager::machine_update_module::{
        AutomaticFirmwareUpdateReference, DpuReprovisionInitiator,
    },
    model::machine::{machine_id::MachineId, ReprovisionRequest},
    CarbideError,
};

use super::{machine::DbMachineId, DatabaseError};

#[derive(FromRow)]
pub struct DbDpuMachineUpdate {
    pub host_machine_id: DbMachineId,
    pub dpu_machine_id: DbMachineId,
    pub firmware_version: String,
    pub product_name: String,
}

pub struct DpuMachineUpdate {
    pub host_machine_id: MachineId,
    pub dpu_machine_id: MachineId,
    pub firmware_version: String,
    pub product_name: String,
}

impl From<DbDpuMachineUpdate> for DpuMachineUpdate {
    fn from(value: DbDpuMachineUpdate) -> Self {
        DpuMachineUpdate {
            host_machine_id: value.host_machine_id.into(),
            dpu_machine_id: value.dpu_machine_id.into(),
            firmware_version: value.firmware_version,
            product_name: value.product_name,
        }
    }
}

impl DpuMachineUpdate {
    /// Find DPUs and the corresponding host that needs to have its firmware updated.
    /// DPUs can be updated when:
    /// 1. the installed firmware does not match the expected firmware
    /// 2. the DPU is not marked for reprovisioning
    /// 3. the DPU is not marked for maintenance.
    ///
    pub async fn find_available_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_versions: &HashMap<String, String>,
        limit: Option<i32>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        if limit.is_some_and(|l| l <= 0) {
            return Ok(vec![]);
        }
        if expected_firmware_versions.is_empty() {
            return Err(DatabaseError {
                file: file!(),
                line: line!(),
                query: "find_available_outdated_dpus",
                source: sqlx::Error::Configuration(Box::new(CarbideError::InvalidArgument(
                    "Missing expected_firmware_versions".to_string(),
                ))),
            });
        }

        let mut query = r#"SELECT mi.machine_id as host_machine_id, m.id as dpu_machine_id,
            mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version,
            topology->'discovery_data'->'Info'->'dmi_data'->>'product_name' as product_name
            FROM machines m
            INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
            INNER JOIN machine_topologies mt ON m.id = mt.machine_id
            WHERE m.reprovisioning_requested IS NULL 
            AND mi.machine_id != mi.attached_dpu_machine_id
            AND m.controller_state = '{"state": "ready"}'
            AND m.maintenance_start_time IS NULL 
            AND (network_status_observation->'health_status'->>'is_healthy')::boolean is true 
            "#.to_owned();

        let mut bind_index = 1;
        for (ind, _) in expected_firmware_versions.iter().enumerate() {
            if ind == 0 {
                query += " AND (\n"
            } else {
                query += " OR ";
            }
            query += &format!(
                "(topology->'discovery_data'->'Info'->'dmi_data'->>'product_name' = ${} \n",
                bind_index
            );
            query += &format!("AND mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' != ${}\n)", bind_index + 1);
            bind_index += 2;
        }
        query += ")\n";

        if limit.is_some() {
            query += &format!(" LIMIT ${};", bind_index);
        }

        let mut q = sqlx::query_as::<_, DbDpuMachineUpdate>(&query);
        for (product_name, expected_version) in expected_firmware_versions {
            q = q.bind(product_name).bind(expected_version);
        }

        if let Some(limit) = limit {
            q = q.bind(limit);
        }

        let result = q
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_available_outdated_dpus", e))?;

        Ok(result.into_iter().map(DbDpuMachineUpdate::into).collect())
    }

    pub async fn find_unavailable_outdated_dpus(
        txn: &mut Transaction<'_, Postgres>,
        expected_firmware_versions: &HashMap<String, String>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let mut query = r#"SELECT mi.machine_id as host_machine_id, m.id as dpu_machine_id,
            mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version,
            topology->'discovery_data'->'Info'->'dmi_data'->>'product_name' as product_name
            FROM machines m
            INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
            INNER JOIN machine_topologies mt ON m.id = mt.machine_id
            WHERE m.reprovisioning_requested IS NULL 
            AND mi.machine_id != mi.attached_dpu_machine_id 
            AND (m.controller_state != '{"state": "ready"}'
            OR (network_status_observation->'health_status'->>'is_healthy')::boolean is false) 
            AND m.maintenance_start_time IS NULL "#.to_owned();

        let mut bind_index = 1;
        for (ind, _) in expected_firmware_versions.iter().enumerate() {
            if ind == 0 {
                query += " AND (\n"
            } else {
                query += " OR ";
            }
            query += &format!(
                "(topology->'discovery_data'->'Info'->'dmi_data'->>'product_name' = ${} \n",
                bind_index
            );
            query += &format!("AND mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' != ${}\n)", bind_index + 1);
            bind_index += 2;
        }
        query += ")\n";

        let mut q = sqlx::query_as::<_, DbDpuMachineUpdate>(&query);
        for (product_name, expected_version) in expected_firmware_versions {
            q = q.bind(product_name).bind(expected_version);
        }

        let result = q
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_available_outdated_dpus", e))?;

        Ok(result.into_iter().map(DbDpuMachineUpdate::into).collect())
    }

    pub async fn get_fw_updates_running_count(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<i64, DatabaseError> {
        let query = r#"SELECT COUNT(*) as count FROM machines m
            WHERE reprovisioning_requested->>'initiator' LIKE 'AutomaticDpuFirmwareUpdate%' 
            AND reprovisioning_requested->>'started_at' IS NOT NULL;"#;
        let (count,): (i64,) = sqlx::query_as(query)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_available_outdated_dpus", e))?;

        Ok(count)
    }

    pub async fn trigger_reprovisioning_for_managed_host(
        txn: &mut Transaction<'_, Postgres>,
        machine_update: &DpuMachineUpdate,
        expected_versions: HashMap<String, String>,
    ) -> Result<(), DatabaseError> {
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

        let initiator = DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
            from: machine_update.firmware_version.clone(),
            to: expected_version.clone(),
        });
        let req = ReprovisionRequest {
            requested_at: chrono::Utc::now(),
            initiator: initiator.to_string(),
            update_firmware: true,
            started_at: None,
            user_approval_received: false,
        };

        let query = r#"UPDATE machines SET reprovisioning_requested=$1, maintenance_reference=$2, maintenance_start_time=NOW() WHERE controller_state = '{"state": "ready"}' AND id=$3 AND maintenance_reference IS NULL;"#;
        sqlx::query(query)
            .bind(sqlx::types::Json(req))
            .bind(initiator.to_string())
            .bind(machine_update.dpu_machine_id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let query = r#"UPDATE machines SET maintenance_reference=$1, maintenance_start_time=NOW() WHERE controller_state = '{"state": "ready"}' AND id=$2 AND maintenance_reference IS NULL;"#;
        sqlx::query(query)
            .bind(initiator.to_string())
            .bind(machine_update.host_machine_id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

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

        let result: Vec<DbDpuMachineUpdate> = sqlx::query_as::<_, DbDpuMachineUpdate>(query)
            .bind(&reference)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(result.into_iter().map(DpuMachineUpdate::from).collect())
    }

    pub async fn get_updated_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DpuMachineUpdate>, DatabaseError> {
        let reference = AutomaticFirmwareUpdateReference::REF_NAME.to_string() + "%";

        let query = r#"SELECT mi.machine_id as host_machine_id, mi.attached_dpu_machine_id as dpu_machine_id,
        mt.topology->'discovery_data'->'Info'->'dpu_info'->>'firmware_version' AS firmware_version,
        topology->'discovery_data'->'Info'->'dmi_data'->>'product_name' as product_name
        FROM machines m
        INNER JOIN machine_interfaces mi ON m.id = mi.attached_dpu_machine_id
        INNER JOIN machine_topologies mt ON m.id = mt.machine_id
        WHERE mi.machine_id != mi.attached_dpu_machine_id
        AND m.controller_state = '{"state": "ready"}'
        AND m.maintenance_reference like $1
        AND m.reprovisioning_requested IS NULL"#;

        let updated_machines: Vec<DbDpuMachineUpdate> =
            sqlx::query_as::<_, DbDpuMachineUpdate>(query)
                .bind(&reference)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(updated_machines
            .into_iter()
            .map(DpuMachineUpdate::from)
            .collect())
    }
}
