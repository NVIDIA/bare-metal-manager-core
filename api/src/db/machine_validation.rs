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

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::DatabaseError, model::machine::machine_id::MachineId, CarbideError, CarbideResult,
};

use super::{
    machine::{DbMachineId, Machine, MachineSearchConfig},
    ObjectFilter,
};

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
}

impl<'r> FromRow<'r, PgRow> for MachineValidation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let mc_id: DbMachineId = row.try_get("machine_id")?;
        Ok(MachineValidation {
            id: row.try_get("id")?,
            machine_id: mc_id.into_inner(),
            name: row.try_get("name")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
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
            ObjectFilter::All => {
                sqlx::query_as::<_, MachineValidation>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "MachineValidation All", e))?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE result.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, MachineValidation>(&query)
                    .fetch_all(&mut **txn)
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

                sqlx::query_as::<_, MachineValidation>(&query)
                    .fetch_all(&mut **txn)
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
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn create_new_run(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        context: String,
    ) -> Result<Uuid, DatabaseError> {
        let id = uuid::Uuid::new_v4();
        let query = "
        INSERT INTO machine_validation (
            id,
            name,
            machine_id
        )
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING";
        let _ = sqlx::query(query)
            .bind(id)
            .bind(format!("Test_{}", machine_id))
            .bind(machine_id)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut column_name = "discovery_machine_validation_id".to_string();
        if context == "Cleanup" {
            column_name = "cleanup_machine_validation_id".to_string();
        }
        Machine::update_machine_validation_id(machine_id, id, column_name, txn).await?;
        Ok(id)
    }
}
//
// MachineValidation
//

#[derive(Debug, Clone)]
pub struct MachineValidationResult {
    pub validation_id: Uuid,
    name: String,
    description: String,
    stdout: String,
    stderr: String,
    command: String,
    args: String,
    pub context: String,
    exit_code: i32,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
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
        MachineValidationResult::find_by(
            txn,
            ObjectFilter::List(&[
                cleanup_machine_validation_id.to_string(),
                discovery_machine_validation_id.to_string(),
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
            ObjectFilter::All => {
                sqlx::query_as::<_, MachineValidationResult>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_validation_results All", e)
                    })?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE result.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, MachineValidationResult>(&query)
                    .fetch_all(&mut **txn)
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

                sqlx::query_as::<_, MachineValidationResult>(&query)
                    .fetch_all(&mut **txn)
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
            .execute(&mut **txn)
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
            if !result.stderr.is_empty() && result.exit_code != 0 {
                return Ok(Some(result.stderr));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {}
