/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::machine::MachineId;
use model::machine::MachineValidationFilter;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_validation::{
    MachineValidation, MachineValidationState, MachineValidationStatus,
};
use sqlx::PgConnection;
use uuid::Uuid;

use super::ObjectFilter;
use crate::{DatabaseError, DatabaseResult};

pub async fn find_by(
    txn: &mut PgConnection,
    filter: ObjectFilter<'_, String>,
    column: &str,
) -> Result<Vec<MachineValidation>, DatabaseError> {
    let base_query =
        "SELECT * FROM machine_validation result {where} ORDER BY result.start_time".to_owned();

    let custom_results = match filter {
        ObjectFilter::All => sqlx::query_as(&base_query.replace("{where}", ""))
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new("MachineValidation All", e))?,
        ObjectFilter::One(id) => {
            let query = base_query
                .replace("{where}", &format!("WHERE result.{column}='{id}'"))
                .replace("{column}", column);
            sqlx::query_as(&query)
                .fetch_all(txn)
                .await
                .map_err(|e| DatabaseError::new("MachineValidation One", e))?
        }
        ObjectFilter::List(list) => {
            if list.is_empty() {
                return Ok(Vec::new());
            }

            let mut columns = String::new();
            for item in list {
                if !columns.is_empty() {
                    columns.push(',');
                }
                columns.push('\'');
                columns.push_str(item);
                columns.push('\'');
            }
            let query = base_query
                .replace("{where}", &format!("WHERE result.{column} IN ({columns})"))
                .replace("{column}", column);

            sqlx::query_as(&query)
                .fetch_all(txn)
                .await
                .map_err(|e| DatabaseError::new("machine_validation List", e))?
        }
    };

    Ok(custom_results)
}

pub async fn update_status(
    txn: &mut PgConnection,
    uuid: &Uuid,
    status: MachineValidationStatus,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_validation SET state=$2 WHERE id=$1 RETURNING *";
    let _id = sqlx::query_as::<_, MachineValidation>(query)
        .bind(uuid)
        .bind(status.state.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
pub async fn update_end_time(
    txn: &mut PgConnection,
    uuid: &Uuid,
    status: &MachineValidationStatus,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_validation SET end_time=NOW(),state=$2 WHERE id=$1 RETURNING *";
    let _id = sqlx::query_as::<_, MachineValidation>(query)
        .bind(uuid)
        .bind(status.state.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn update_run(
    txn: &mut PgConnection,
    uuid: &Uuid,
    total: i32,
    duration_to_complete: i64,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_validation SET duration_to_complete=$2,total=$3,completed=0  WHERE id=$1 RETURNING *";
    let _id = sqlx::query_as::<_, MachineValidation>(query)
        .bind(uuid)
        .bind(duration_to_complete)
        .bind(total)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
pub async fn create_new_run(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    context: String,
    filter: MachineValidationFilter,
) -> Result<Uuid, DatabaseError> {
    let id = uuid::Uuid::new_v4();
    let query = "
        INSERT INTO machine_validation (
            id,
            name,
            machine_id,
            filter,
            context,
            end_time,
            description,
            state
        )
        VALUES ($1, $2, $3, $4, $5, NULL, $6, $7)
        ON CONFLICT DO NOTHING";
    // TODO fetch total number of test and repopulate the status
    let status = MachineValidationStatus {
        state: MachineValidationState::Started,
        ..MachineValidationStatus::default()
    };
    let _ = sqlx::query(query)
        .bind(id)
        .bind(format!("Test_{machine_id}"))
        .bind(machine_id)
        .bind(sqlx::types::Json(filter))
        .bind(&context)
        .bind(format!("Running validation on {machine_id}"))
        .bind(status.state.to_string())
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut column_name = "discovery_machine_validation_id".to_string();
    if context == "Cleanup" {
        column_name = "cleanup_machine_validation_id".to_string();
    } else if context == "OnDemand" {
        column_name = "on_demand_machine_validation_id".to_string();
    }
    crate::machine::update_machine_validation_id(machine_id, id, column_name, txn).await?;

    // Reset machine validation health report into initial state
    let health_report = health_report::HealthReport::empty("machine-validation".to_string());
    crate::machine::update_machine_validation_health_report(txn, machine_id, &health_report)
        .await?;

    Ok(id)
}

pub async fn find(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    include_history: bool,
) -> DatabaseResult<Vec<MachineValidation>> {
    if include_history {
        return find_by_machine_id(txn, machine_id).await;
    };
    let machine =
        match crate::machine::find_one(txn, machine_id, MachineSearchConfig::default()).await {
            Err(err) => {
                tracing::warn!(%machine_id, error = %err, "failed loading machine");
                return Err(DatabaseError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                tracing::info!(%machine_id, "machine not found");
                return Err(DatabaseError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
            Ok(Some(m)) => m,
        };
    let discovery_machine_validation_id =
        machine.discovery_machine_validation_id.unwrap_or_default();
    let cleanup_machine_validation_id = machine.cleanup_machine_validation_id.unwrap_or_default();

    let on_demand_machine_validation_id =
        machine.on_demand_machine_validation_id.unwrap_or_default();
    find_by(
        txn,
        ObjectFilter::List(&[
            cleanup_machine_validation_id.to_string(),
            discovery_machine_validation_id.to_string(),
            on_demand_machine_validation_id.to_string(),
        ]),
        "id",
    )
    .await
}

pub async fn find_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<Vec<MachineValidation>> {
    find_by(
        txn,
        ObjectFilter::List(&[machine_id.to_string()]),
        "machine_id",
    )
    .await
}

pub async fn find_active_machine_validation_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<MachineValidation> {
    let ret = find_by_machine_id(txn, machine_id).await?;
    for iter in ret {
        if iter.end_time.is_none() {
            return Ok(iter);
        }
    }
    Err(DatabaseError::InvalidArgument(format!(
        "Not active machine validation in  {machine_id:?} "
    )))
}

pub async fn find_by_id(
    txn: &mut PgConnection,
    validation_id: &Uuid,
) -> DatabaseResult<MachineValidation> {
    let machine_validation =
        find_by(txn, ObjectFilter::One(validation_id.to_string()), "id").await?;

    if !machine_validation.is_empty() {
        return Ok(machine_validation[0].clone());
    }
    Err(DatabaseError::InvalidArgument(format!(
        "Validaion Id not found  {validation_id:?} "
    )))
}

pub async fn find_all(txn: &mut PgConnection) -> DatabaseResult<Vec<MachineValidation>> {
    find_by(txn, ObjectFilter::All, "").await
}

pub async fn mark_machine_validation_complete(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    uuid: &Uuid,
    status: MachineValidationStatus,
) -> DatabaseResult<()> {
    //Mark machine validation request to false
    crate::machine::set_machine_validation_request(txn, machine_id, false).await?;

    crate::machine::update_machine_validation_time(machine_id, txn).await?;

    //TODO repopulate the status
    update_end_time(txn, uuid, &status).await?;
    Ok(())
}
