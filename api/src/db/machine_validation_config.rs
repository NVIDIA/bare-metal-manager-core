/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{db::DatabaseError, CarbideError, CarbideResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct MachineValidationExternalConfig {
    pub name: String,
    pub description: String,
    pub config: Vec<u8>,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationExternalConfig {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationExternalConfig {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            config: row.try_get("config")?,
        })
    }
}

impl From<MachineValidationExternalConfig> for rpc::forge::MachineValidationExternalConfig {
    fn from(value: MachineValidationExternalConfig) -> Self {
        rpc::forge::MachineValidationExternalConfig {
            name: value.name,
            config: value.config,
            description: Some(value.description),
        }
    }
}
impl TryFrom<rpc::forge::MachineValidationExternalConfig> for MachineValidationExternalConfig {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineValidationExternalConfig) -> CarbideResult<Self> {
        Ok(MachineValidationExternalConfig {
            name: value.name,
            description: "".to_string(),
            config: value.config,
        })
    }
}

impl MachineValidationExternalConfig {
    pub async fn find_config_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> CarbideResult<Self> {
        let query = "SELECT * FROM machine_validation_external_config WHERE name=$1";
        sqlx::query_as(query)
            .bind(name)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))
    }

    pub async fn save(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        description: &str,
        config: &Vec<u8>,
    ) -> CarbideResult<()> {
        let query =
            "INSERT INTO machine_validation_external_config (name, description, config) VALUES ($1, $2, $3) RETURNING name";

        sqlx::query_as(query)
            .bind(name)
            .bind(description)
            .bind(config.as_slice())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }

    async fn update(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        config: &Vec<u8>,
    ) -> CarbideResult<()> {
        let query =
            "UPDATE machine_validation_external_config SET config=$2 WHERE name=$1 RETURNING name";

        sqlx::query_as(query)
            .bind(name)
            .bind(config.as_slice())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }

    pub async fn create_or_update(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
        description: &str,
        data: &Vec<u8>,
    ) -> CarbideResult<()> {
        let _ = match Self::save(txn, name, description, data).await {
            Ok(_) => return Ok(()),
            Err(_) => Self::update(txn, name, data).await,
        };
        Ok(())
    }
}
#[cfg(test)]
mod test {}
