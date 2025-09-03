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

use sqlx::{FromRow, PgConnection, Row, postgres::PgRow};
use std::str::FromStr;

use crate::db::FilterableQueryBuilder;
use crate::{
    CarbideError, CarbideResult,
    db::{ColumnInfo, DatabaseError, ObjectColumnFilter},
};
use forge_uuid::machine::MachineInterfaceId;

///
/// A custom boot response is a representation of custom data for booting machines, either with pxe or user-data
///
#[derive(Debug, sqlx::Encode)]
pub struct MachineBootOverride {
    pub machine_interface_id: MachineInterfaceId,
    pub custom_pxe: Option<String>,
    pub custom_user_data: Option<String>,
}

#[derive(Clone, Copy)]
struct MachineInterfaceIdColumn;
impl ColumnInfo<'_> for MachineInterfaceIdColumn {
    type TableType = MachineBootOverride;
    type ColumnType = MachineInterfaceId;
    fn column_name(&self) -> &'static str {
        "machine_interface_id"
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
        txn: &mut PgConnection,
        machine_interface_id: MachineInterfaceId,
        custom_pxe: Option<String>,
        custom_user_data: Option<String>,
    ) -> CarbideResult<Option<Self>> {
        let query = "INSERT INTO machine_boot_override VALUES ($1, $2, $3) RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_interface_id)
            .bind(custom_pxe)
            .bind(custom_user_data)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(Some(res))
    }

    pub async fn update_or_insert(&self, txn: &mut PgConnection) -> CarbideResult<()> {
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
                    .execute(txn)
                    .await
                    .map_err(|e| DatabaseError::query(query, e))?;
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
        txn: &mut PgConnection,
        machine_interface_id: MachineInterfaceId,
    ) -> CarbideResult<()> {
        let query = "DELETE FROM machine_boot_override WHERE machine_interface_id = $1";

        sqlx::query(query)
            .bind(machine_interface_id)
            .execute(txn)
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::query(query, e))
            .map_err(CarbideError::from)
    }

    pub async fn find_optional(
        txn: &mut PgConnection,
        machine_interface_id: MachineInterfaceId,
    ) -> CarbideResult<Option<MachineBootOverride>> {
        let mut interfaces = MachineBootOverride::find_by(
            txn,
            ObjectColumnFilter::One(MachineInterfaceIdColumn, &machine_interface_id),
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

    async fn find_by<'a, C: ColumnInfo<'a, TableType = MachineBootOverride>>(
        txn: &mut PgConnection,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<MachineBootOverride>, DatabaseError> {
        let mut query =
            FilterableQueryBuilder::new("SELECT * FROM machine_boot_override").filter(&filter);

        query
            .build_query_as()
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query.sql(), e))
    }
}
