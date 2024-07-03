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
use std::str::FromStr;

use crate::{
    db::machine_interface::MachineInterfaceId,
    db::{ColumnInfo, DatabaseError, ObjectColumnFilter},
    CarbideError, CarbideResult,
};

///
/// A custom boot response is a representation of custom data for booting machines, either with pxe or user-data
///
#[derive(Debug, sqlx::Encode)]
pub struct MachineBootOverride {
    pub machine_interface_id: MachineInterfaceId,
    pub custom_pxe: Option<String>,
    pub custom_user_data: Option<String>,
}

#[derive(Clone)]
struct MachineInterfaceIdColumn;
impl ColumnInfo for MachineInterfaceIdColumn {
    type ColumnType = MachineInterfaceId;
    fn column_name(&self) -> String {
        "machine_interface_id".to_string()
    }
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

impl From<MachineBootOverride> for rpc::forge::MachineBootOverride {
    fn from(value: MachineBootOverride) -> Self {
        rpc::forge::MachineBootOverride {
            machine_interface_id: Some(value.machine_interface_id.into()),
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        }
    }
}

impl TryFrom<rpc::forge::MachineBootOverride> for MachineBootOverride {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineBootOverride) -> CarbideResult<Self> {
        let machine_interface_id = match value.machine_interface_id {
            Some(machine_interface_id) => {
                MachineInterfaceId::from_str(&machine_interface_id.value)?
            }
            None => return Err(CarbideError::MissingArgument("machine_interface_id")),
        };
        Ok(MachineBootOverride {
            machine_interface_id,
            custom_pxe: value.custom_pxe,
            custom_user_data: value.custom_user_data,
        })
    }
}

impl MachineBootOverride {
    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: MachineInterfaceId,
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

    pub async fn update_or_insert(&self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<()> {
        match MachineBootOverride::find_optional(txn, self.machine_interface_id).await? {
            Some(existing_mbo) => {
                let custom_pxe = if self.custom_pxe.is_some() {
                    self.custom_pxe.clone()
                } else {
                    existing_mbo.custom_pxe
                };

                let custom_user_data = if self.custom_user_data.is_some() {
                    self.custom_user_data.clone()
                } else {
                    existing_mbo.custom_user_data
                };

                let query = r#"UPDATE machine_boot_override SET custom_pxe=$1, custom_user_data=$2 WHERE machine_interface_id=$3;"#;

                sqlx::query(query)
                    .bind(custom_pxe)
                    .bind(custom_user_data)
                    .bind(self.machine_interface_id)
                    .execute(&mut **txn)
                    .await
                    .map_err(|e| {
                        CarbideError::from(DatabaseError::new(file!(), line!(), query, e))
                    })?;
            }
            None => {
                MachineBootOverride::create(
                    txn,
                    self.machine_interface_id,
                    self.custom_pxe.clone(),
                    self.custom_user_data.clone(),
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn clear(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: MachineInterfaceId,
    ) -> CarbideResult<()> {
        let query = "DELETE FROM machine_boot_override WHERE machine_interface_id = $1";

        sqlx::query(query)
            .bind(machine_interface_id)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn find_optional(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: MachineInterfaceId,
    ) -> CarbideResult<Option<MachineBootOverride>> {
        let mut interfaces = MachineBootOverride::find_by(
            txn,
            ObjectColumnFilter::One(MachineInterfaceIdColumn, machine_interface_id),
        )
        .await
        .map_err(CarbideError::from)?;
        match interfaces.len() {
            0 => Ok(None),
            1 => Ok(Some(interfaces.remove(0))),
            _ => Err(CarbideError::FindOneReturnedManyResultsError(
                machine_interface_id.0,
            )),
        }
    }

    async fn find_by<'a, C, T>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C, T>,
    ) -> Result<Vec<MachineBootOverride>, DatabaseError>
    where
        C: ColumnInfo<ColumnType = T>,
        T: sqlx::Type<sqlx::Postgres>
            + Send
            + Sync
            + sqlx::Encode<'a, sqlx::Postgres>
            + sqlx::postgres::PgHasArrayType
            + Clone,
    {
        let mut base_query = sqlx::QueryBuilder::new("SELECT * FROM machine_boot_override pxe");

        let custom_pxes = match filter {
            ObjectColumnFilter::All => base_query
                .build_query_as::<MachineBootOverride>()
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "machine_boot_override All", e)
                })?,
            ObjectColumnFilter::One(column, id) => base_query
                .push(format!(" WHERE pxe.{}=", column.column_name()))
                .push_bind(id)
                .build_query_as::<MachineBootOverride>()
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "machine_boot_override One", e)
                })?,
            ObjectColumnFilter::List(column, list) => {
                if list.is_empty() {
                    return Ok(Vec::new());
                }

                base_query
                    .push(format!(" WHERE pxe.{} = ANY(", column.column_name()))
                    .push_bind(list)
                    .push(")")
                    .build_query_as::<MachineBootOverride>()
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
