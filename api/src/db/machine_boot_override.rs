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
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::db::ObjectFilter;
use crate::{db::DatabaseError, CarbideError, CarbideResult};

///
/// A custom boot response is a representation of custom data for booting machines, either with pxe or user-data
///
#[derive(Debug)]
pub struct MachineBootOverride {
    pub machine_interface_id: uuid::Uuid,
    pub custom_pxe: Option<String>,
    pub custom_user_data: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for MachineBootOverride {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineBootOverride {
            machine_interface_id: row.try_get("machine_interface_id")?,
            custom_pxe: row.try_get("custom_pxe")?,
            custom_user_data: row.try_get("custom_user_data")?,
        })
    }
}

impl MachineBootOverride {
    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: uuid::Uuid,
        custom_pxe: Option<String>,
        custom_user_data: Option<String>,
    ) -> CarbideResult<Option<Self>> {
        let query = "INSERT INTO machine_boot_override VALUES ($1, $2, $3) RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_interface_id)
            .bind(custom_pxe)
            .bind(custom_user_data)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(Some(res))
    }

    pub async fn find_optional(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: uuid::Uuid,
    ) -> CarbideResult<Option<MachineBootOverride>> {
        let mut interfaces = MachineBootOverride::find_by(
            txn,
            ObjectFilter::One(machine_interface_id.to_string()),
            "machine_interface_id",
        )
        .await
        .map_err(CarbideError::from)?;
        match interfaces.len() {
            0 => Ok(None),
            1 => Ok(Some(interfaces.remove(0))),
            _ => Err(CarbideError::FindOneReturnedManyResultsError(
                machine_interface_id,
            )),
        }
    }

    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<MachineBootOverride>, DatabaseError> {
        let base_query = "SELECT * FROM machine_boot_override pxe {where}".to_owned();

        let custom_pxes = match filter {
            ObjectFilter::All => {
                sqlx::query_as::<_, MachineBootOverride>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_boot_override All", e)
                    })?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE pxe.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, MachineBootOverride>(&query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_boot_override One", e)
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
                    .replace("{where}", &format!("WHERE pxe.{column} IN ({})", columns))
                    .replace("{column}", column);

                sqlx::query_as::<_, MachineBootOverride>(&query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_boot_override List", e)
                    })?
            }
        };

        Ok(custom_pxes)
    }
}
