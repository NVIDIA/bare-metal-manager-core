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
use std::ops::DerefMut;

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::DatabaseError, model::machine::MachineValidationFilter, CarbideError, CarbideResult,
};

use super::{
    machine::{Machine, MachineSearchConfig},
    ObjectFilter,
};

use forge_uuid::machine::MachineId;

//
// MachineValidation
//

#[derive(Debug, Clone)]
pub struct MachineValidation {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub name: String,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub filter: Option<MachineValidationFilter>,
}

impl<'r> FromRow<'r, PgRow> for MachineValidation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let filter: Option<sqlx::types::Json<MachineValidationFilter>> = row.try_get("filter")?;

        Ok(MachineValidation {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            name: row.try_get("name")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
            filter: filter.map(|x| x.0),
        })
    }
}
impl MachineValidation {
    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<MachineValidation>, DatabaseError> {
        let base_query = "SELECT * FROM machine_validation result {where}".to_owned();

        let custom_results = match filter {
            ObjectFilter::All => sqlx::query_as(&base_query.replace("{where}", ""))
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "MachineValidation All", e))?,
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE result.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as(&query)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "MachineValidation One", e))?
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
                    .replace(
                        "{where}",
                        &format!("WHERE result.{column} IN ({})", columns),
                    )
                    .replace("{column}", column);

                sqlx::query_as(&query)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_validation List", e)
                    })?
            }
        };

        Ok(custom_results)
    }

    pub async fn update_end_time(
        uuid: &Uuid,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = "UPDATE machine_validation SET end_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(uuid)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn create_new_run(
        txn: &mut Transaction<'_, Postgres>,
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
            end_time
        )
        VALUES ($1, $2, $3, $4, $5, NULL)
        ON CONFLICT DO NOTHING";
        let _ = sqlx::query(query)
            .bind(id)
            .bind(format!("Test_{}", machine_id))
            .bind(machine_id)
            .bind(sqlx::types::Json(filter))
            .bind(context.clone())
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut column_name = "discovery_machine_validation_id".to_string();
        if context == "Cleanup" {
            column_name = "cleanup_machine_validation_id".to_string();
        } else if context == "OnDemand" {
            column_name = "on_demand_machine_validation_id".to_string();
        }
        Machine::update_machine_validation_id(machine_id, id, column_name, txn).await?;

        // Reset machine validation health report into initial state
        let health_report = health_report::HealthReport::empty("machine-validation".to_string());
        Machine::update_machine_validation_health_report(txn, machine_id, &health_report).await?;

        Ok(id)
    }
    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> CarbideResult<Vec<MachineValidation>> {
        MachineValidation::find_by(
            txn,
            ObjectFilter::List(&[machine_id.to_string()]),
            "machine_id",
        )
        .await
        .map_err(CarbideError::from)
    }

    pub async fn find_active_machine_validation_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> CarbideResult<Self> {
        let ret = Self::find_by_machine_id(txn, machine_id).await?;
        for iter in ret {
            if iter.end_time.is_none() {
                return Ok(iter);
            }
        }
        Err(CarbideError::InvalidArgument(format!(
            "Not active machine validation in  {:?} ",
            machine_id
        )))
    }

    pub async fn find_by_id(
        txn: &mut Transaction<'_, Postgres>,
        validation_id: &Uuid,
    ) -> CarbideResult<Self> {
        let machine_validation =
            MachineValidation::find_by(txn, ObjectFilter::One(validation_id.to_string()), "id")
                .await
                .map_err(CarbideError::from)?;

        if !machine_validation.is_empty() {
            return Ok(machine_validation[0].clone());
        }
        Err(CarbideError::InvalidArgument(format!(
            "Validaion Id not found  {:?} ",
            validation_id
        )))
    }

    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<MachineValidation>> {
        MachineValidation::find_by(txn, ObjectFilter::All, "")
            .await
            .map_err(CarbideError::from)
    }
}

impl From<MachineValidation> for rpc::forge::MachineValidationRun {
    fn from(value: MachineValidation) -> Self {
        let mut end_time = None;
        if value.end_time.is_some() {
            end_time = Some(value.end_time.unwrap_or_default().into());
        }
        let start_time = Some(value.start_time.unwrap_or_default().into());
        rpc::forge::MachineValidationRun {
            validation_id: Some(value.id.into()),
            name: value.name,
            start_time,
            end_time,
            machine_id: Some(rpc::common::MachineId {
                id: value.machine_id.to_string(),
            }),
        }
    }
}

//
// MachineValidationResult
//

#[derive(Debug, Clone)]
pub struct MachineValidationResult {
    pub validation_id: Uuid,
    pub name: String,
    pub description: String,
    pub stdout: String,
    pub stderr: String,
    pub command: String,
    pub args: String,
    pub context: String,
    pub exit_code: i32,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationResult {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationResult {
            validation_id: row.try_get("machine_validation_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            command: row.try_get("command")?,
            args: row.try_get("args")?,
            context: row.try_get("context")?,
            stdout: row.try_get("stdout")?,
            stderr: row.try_get("stderr")?,
            exit_code: row.try_get("exit_code")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
        })
    }
}

impl TryFrom<rpc::forge::MachineValidationResult> for MachineValidationResult {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineValidationResult) -> CarbideResult<Self> {
        let val_id =
            Uuid::try_from(value.validation_id.unwrap_or_default()).map_err(CarbideError::from)?;
        let start_time = match value.start_time {
            Some(time) => {
                DateTime::from_timestamp(time.clone().seconds, time.nanos.try_into().unwrap())
                    .unwrap()
            }
            None => Utc::now(),
        };
        let end_time = match value.end_time {
            Some(time) => {
                DateTime::from_timestamp(time.clone().seconds, time.nanos.try_into().unwrap())
                    .unwrap()
            }
            None => Utc::now(),
        };
        Ok(MachineValidationResult {
            validation_id: val_id,
            command: value.command,
            name: value.name,
            description: value.description,
            args: value.args,
            context: value.context,
            stdout: value.std_out,
            stderr: value.std_err,
            exit_code: value.exit_code,
            start_time,
            end_time,
        })
    }
}

impl From<MachineValidationResult> for rpc::forge::MachineValidationResult {
    fn from(value: MachineValidationResult) -> Self {
        rpc::forge::MachineValidationResult {
            validation_id: Some(value.validation_id.into()),
            command: value.command,
            args: value.args,
            std_out: value.stdout,
            std_err: value.stderr,
            name: value.name,
            description: value.description,
            context: value.context,
            exit_code: value.exit_code,
            start_time: Some(value.start_time.into()),
            end_time: Some(value.end_time.into()),
        }
    }
}
impl MachineValidationResult {
    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        include_history: bool,
    ) -> CarbideResult<Vec<MachineValidationResult>> {
        if include_history {
            // Fetch all validation_id from machine_validation table
            let machine_validation = MachineValidation::find_by(
                txn,
                ObjectFilter::List(&[machine_id.to_string()]),
                "machine_id",
            )
            .await?;

            let mut columns = Vec::new();
            for item in machine_validation {
                columns.push(item.id.to_string());
            }
            return MachineValidationResult::find_by(
                txn,
                ObjectFilter::List(&columns),
                "machine_validation_id",
            )
            .await
            .map_err(CarbideError::from);
        };
        let machine = match Machine::find_one(txn, machine_id, MachineSearchConfig::default()).await
        {
            Err(err) => {
                tracing::warn!(%machine_id, error = %err, "failed loading machine");
                return Err(CarbideError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                tracing::info!(%machine_id, "machine not found");
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
            Ok(Some(m)) => m,
        };
        let discovery_machine_validation_id = machine
            .discovery_machine_validation_id()
            .unwrap_or_default();
        let cleanup_machine_validation_id =
            machine.cleanup_machine_validation_id().unwrap_or_default();

        let on_demand_machine_validation_id = machine
            .on_demand_machine_validation_id()
            .unwrap_or_default();
        MachineValidationResult::find_by(
            txn,
            ObjectFilter::List(&[
                cleanup_machine_validation_id.to_string(),
                discovery_machine_validation_id.to_string(),
                on_demand_machine_validation_id.to_string(),
            ]),
            "machine_validation_id",
        )
        .await
        .map_err(CarbideError::from)
    }

    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<MachineValidationResult>, DatabaseError> {
        let base_query = "SELECT * FROM machine_validation_results result {where}".to_owned();

        let custom_results = match filter {
            ObjectFilter::All => sqlx::query_as(&base_query.replace("{where}", ""))
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "machine_validation_results All", e)
                })?,
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE result.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as(&query)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_validation_results One", e)
                    })?
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
                    .replace(
                        "{where}",
                        &format!("WHERE result.{column} IN ({})", columns),
                    )
                    .replace("{column}", column);

                sqlx::query_as(&query)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_validation_results List", e)
                    })?
            }
        };

        Ok(custom_results)
    }

    pub async fn create(&self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<()> {
        let query = "
        INSERT INTO machine_validation_results (
            name,
            description,
            command,
            args,
            stdout,
            stderr,
            context,
            exit_code,
            machine_validation_id,
            start_time,
            end_time
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT DO NOTHING";
        let _result = sqlx::query(query)
            .bind(&self.name)
            .bind(&self.description)
            .bind(&self.command)
            .bind(&self.args)
            .bind(&self.stdout)
            .bind(&self.stderr)
            .bind(&self.context)
            .bind(self.exit_code)
            .bind(self.validation_id)
            .bind(self.start_time)
            .bind(self.end_time)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn validate(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> CarbideResult<Option<String>> {
        let db_results =
            MachineValidationResult::find_by_machine_id(txn, machine_id, false).await?;

        for result in db_results {
            if result.exit_code != 0 {
                return Ok(Some(format!("{} is failed", result.name)));
            }
        }
        Ok(None)
    }

    pub async fn validate_current_context(
        txn: &mut Transaction<'_, Postgres>,
        id: &rpc::Uuid,
    ) -> CarbideResult<Option<String>> {
        let db_results = MachineValidationResult::find_by(
            txn,
            ObjectFilter::List(&[id.to_string()]),
            "machine_validation_id",
        )
        .await
        .map_err(CarbideError::from)?;

        for result in db_results {
            if result.exit_code != 0 {
                return Ok(Some(format!("{} is failed", result.name)));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {}
