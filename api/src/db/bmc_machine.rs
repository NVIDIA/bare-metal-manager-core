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

use futures::StreamExt;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::model::config_version::ConfigVersion;
use crate::model::{
    bmc_machine::{BmcMachineState, BmcMachineType},
    config_version::Versioned,
};
use crate::{CarbideError, CarbideResult};

use super::{DatabaseError, ObjectFilter};

#[derive(Debug, Clone)]
pub struct BmcMachine {
    pub id: Uuid,
    pub machine_interface_id: Uuid,
    pub bmc_type: BmcMachineType,
    pub controller_state: Versioned<BmcMachineState>,
}

impl<'r> FromRow<'r, PgRow> for BmcMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let controller_state: sqlx::types::Json<BmcMachineState> =
            row.try_get("controller_state")?;
        Ok(BmcMachine {
            id: row.try_get("id")?,
            machine_interface_id: row.try_get("machine_interface_id")?,
            bmc_type: row.try_get("bmc_type")?,
            controller_state: Versioned::new(controller_state.0, controller_state_version),
        })
    }
}

impl BmcMachine {
    pub async fn find_or_create_bmc_machine(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: Uuid,
        bmc_type: BmcMachineType,
    ) -> CarbideResult<Self> {
        let mut bmc_machine = BmcMachine::find_by(
            txn,
            ObjectFilter::One(machine_interface_id.to_string()),
            "machine_interface_id",
        )
        .await?;
        if bmc_machine.is_empty() {
            Ok(BmcMachine::create(txn, machine_interface_id, bmc_type).await?)
        } else {
            Ok(bmc_machine.remove(0))
        }
    }

    pub async fn get_by_id(txn: &mut Transaction<'_, Postgres>, id: Uuid) -> CarbideResult<Self> {
        BmcMachine::find_by(txn, ObjectFilter::One(id.to_string()), "id")
            .await?
            .first()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_machine",
                id: id.to_string(),
            })
            .cloned()
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: Uuid,
        bmc_type: BmcMachineType,
    ) -> CarbideResult<Self> {
        match bmc_type {
            BmcMachineType::Dpu => {
                let state_version = ConfigVersion::initial();
                let query = "INSERT INTO bmc_machine
                        (machine_interface_id, bmc_type, controller_state_version, controller_state)
                        VALUES
                        ($1::uuid, $2, $3, $4 ) RETURNING id";
                let machine_id: (Uuid,) = sqlx::query_as(query)
                    .bind(machine_interface_id)
                    .bind(bmc_type)
                    .bind(state_version.version_string())
                    .bind(sqlx::types::Json(BmcMachineState::Init))
                    .fetch_one(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
                BmcMachine::get_by_id(txn, machine_id.0).await
            }
            BmcMachineType::Host => todo!(),
        }
    }

    pub async fn list_bmc_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let query = "SELECT id FROM bmc_machine";
        let mut results = Vec::new();
        let mut bmc_id_stream = sqlx::query_as::<_, BmcMachineId>(query).fetch(txn);
        while let Some(maybe_id) = bmc_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
    }

    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<BmcMachine>, DatabaseError> {
        let base_query = "SELECT * FROM bmc_machine bm {where}".to_owned();

        let machines = match filter {
            ObjectFilter::All => {
                sqlx::query_as::<_, BmcMachine>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine All", e))?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE bm.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, BmcMachine>(&query)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine One", e))?
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
                    .replace("{where}", &format!("WHERE bm.{column} IN ({})", columns))
                    .replace("{column}", column);

                sqlx::query_as::<_, BmcMachine>(&query)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine List", e))?
            }
        };

        Ok(machines)
    }

    /// Updates the BMC machine state that is owned by the state controller
    /// under the premise that the current controller state version didn't change.
    ///
    /// Returns `true` if the state could be updated, and `false` if the object
    /// either doesn't exist anymore or is at a different version.
    pub async fn try_update_controller_state(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &BmcMachineState,
    ) -> Result<bool, DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE bmc_machine SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<BmcMachineId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(machine_id)
            .bind(&expected_version_str)
            .fetch_one(&mut *txn)
            .await;

        match query_result {
            Ok(_machine_id) => Ok(true),
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct BmcMachineId(uuid::Uuid);

impl From<BmcMachineId> for uuid::Uuid {
    fn from(id: BmcMachineId) -> Self {
        id.0
    }
}
