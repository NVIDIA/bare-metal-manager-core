/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use carbide_uuid::machine::MachineId;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_validation::MachineValidationResult;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult, ObjectFilter, machine_validation_suites};

pub async fn find_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    include_history: bool,
) -> DatabaseResult<Vec<MachineValidationResult>> {
    if include_history {
        // Fetch all validation_id from machine_validation table
        let machine_validation = crate::machine_validation::find_by(
            txn,
            ObjectFilter::List(&[machine_id.to_string()]),
            "machine_id",
        )
        .await?;

        let mut columns = Vec::new();
        for item in machine_validation {
            columns.push(item.id.to_string());
        }
        return find_by(txn, ObjectFilter::List(&columns), "machine_validation_id").await;
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
        "machine_validation_id",
    )
    .await
}

async fn find_by(
    txn: &mut PgConnection,
    filter: ObjectFilter<'_, String>,
    column: &str,
) -> Result<Vec<MachineValidationResult>, DatabaseError> {
    let base_query =
        "SELECT * FROM machine_validation_results result {where} ORDER BY result.start_time"
            .to_owned();

    let custom_results = match filter {
        ObjectFilter::All => sqlx::query_as(&base_query.replace("{where}", ""))
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new("machine_validation_results All", e))?,
        ObjectFilter::One(id) => {
            let query = base_query
                .replace("{where}", &format!("WHERE result.{column}='{id}'"))
                .replace("{column}", column);
            sqlx::query_as(&query)
                .fetch_all(txn)
                .await
                .map_err(|e| DatabaseError::new("machine_validation_results One", e))?
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
                .map_err(|e| DatabaseError::new("machine_validation_results List", e))?
        }
    };

    Ok(custom_results)
}

pub async fn create(value: MachineValidationResult, txn: &mut PgConnection) -> DatabaseResult<()> {
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
            end_time,
            test_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT DO NOTHING";
    let _result = sqlx::query(query)
        .bind(&value.name)
        .bind(&value.description)
        .bind(&value.command)
        .bind(&value.args)
        .bind(&value.stdout)
        .bind(&value.stderr)
        .bind(&value.context)
        .bind(value.exit_code)
        .bind(value.validation_id)
        .bind(value.start_time)
        .bind(value.end_time)
        .bind(
            value
                .test_id
                .clone()
                .unwrap_or(machine_validation_suites::generate_test_id(&value.name)),
        )
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn validate_current_context(
    txn: &mut PgConnection,
    id: &rpc::Uuid,
) -> DatabaseResult<Option<String>> {
    let db_results = find_by(
        txn,
        ObjectFilter::List(&[id.to_string()]),
        "machine_validation_id",
    )
    .await?;

    for result in db_results {
        if result.exit_code != 0 {
            return Ok(Some(format!("{} is failed", result.name)));
        }
    }
    Ok(None)
}

pub async fn find_by_validation_id(
    txn: &mut PgConnection,
    id: &uuid::Uuid,
) -> DatabaseResult<Vec<MachineValidationResult>> {
    find_by(
        txn,
        ObjectFilter::List(&[id.to_string()]),
        "machine_validation_id",
    )
    .await
}
