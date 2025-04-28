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
use std::str::FromStr;

use config_version::ConfigVersion;
use sqlx::{FromRow, PgConnection, Row, postgres::PgRow};

use crate::{CarbideError, CarbideResult, db::DatabaseError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct MachineValidationExternalConfig {
    pub name: String,
    pub description: String,
    pub config: Vec<u8>,
    pub version: ConfigVersion,
}

impl<'r> FromRow<'r, PgRow> for MachineValidationExternalConfig {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineValidationExternalConfig {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            config: row.try_get("config")?,
            version: row.try_get("version")?,
        })
    }
}

impl From<MachineValidationExternalConfig> for rpc::forge::MachineValidationExternalConfig {
    fn from(value: MachineValidationExternalConfig) -> Self {
        rpc::forge::MachineValidationExternalConfig {
            name: value.name,
            config: value.config,
            description: Some(value.description),
            version: value.version.version_nr().to_string(),
            timestamp: Some(value.version.timestamp().into()),
        }
    }
}
impl TryFrom<rpc::forge::MachineValidationExternalConfig> for MachineValidationExternalConfig {
    type Error = CarbideError;
    fn try_from(value: rpc::forge::MachineValidationExternalConfig) -> CarbideResult<Self> {
        Ok(MachineValidationExternalConfig {
            name: value.name,
            description: value.description.unwrap_or_default(),
            config: value.config,
            version: ConfigVersion::from_str(&value.version)?,
        })
    }
}

impl MachineValidationExternalConfig {
    pub async fn find_config_by_name(txn: &mut PgConnection, name: &str) -> CarbideResult<Self> {
        let query = "SELECT * FROM machine_validation_external_config WHERE name=$1";
        match sqlx::query_as(query).bind(name).fetch_one(txn).await {
            Ok(val) => Ok(val),
            Err(_) => Err(CarbideError::NotFoundError {
                kind: "machine_validation_external_config",
                id: name.to_owned(),
            }),
        }
    }

    pub async fn save(
        txn: &mut PgConnection,
        name: &str,
        description: &str,
        config: &Vec<u8>,
    ) -> CarbideResult<()> {
        let query = "INSERT INTO machine_validation_external_config (name, description, config, version) VALUES ($1, $2, $3, $4) RETURNING name";

        let _: () = sqlx::query_as(query)
            .bind(name)
            .bind(description)
            .bind(config.as_slice())
            .bind(ConfigVersion::initial())
            .fetch_one(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(())
    }

    async fn update(
        txn: &mut PgConnection,
        name: &str,
        config: &Vec<u8>,
        next_version: ConfigVersion,
    ) -> CarbideResult<()> {
        let query = "UPDATE machine_validation_external_config SET config=$2, version=$3 WHERE name=$1 RETURNING name";

        let _: () = sqlx::query_as(query)
            .bind(name)
            .bind(config.as_slice())
            .bind(next_version)
            .fetch_one(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(())
    }

    pub async fn create_or_update(
        txn: &mut PgConnection,
        name: &str,
        description: &str,
        data: &Vec<u8>,
    ) -> CarbideResult<()> {
        match Self::find_config_by_name(txn, name).await {
            Ok(config) => Self::update(txn, name, data, config.version.increment()).await?,
            Err(_) => Self::save(txn, name, description, data).await?,
        };
        Ok(())
    }

    pub async fn find_configs(txn: &mut PgConnection) -> CarbideResult<Vec<Self>> {
        let query = "SELECT * FROM machine_validation_external_config";

        let names = sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        Ok(names)
    }

    pub async fn remove_config(txn: &mut PgConnection, name: &str) -> CarbideResult<Self> {
        let query = "DELETE FROM machine_validation_external_config WHERE name=$1 RETURNING *";
        match sqlx::query_as(query).bind(name).fetch_one(txn).await {
            Ok(val) => Ok(val),
            Err(_) => Err(CarbideError::NotFoundError {
                kind: "machine_validation_external_config",
                id: name.to_owned(),
            }),
        }
    }
}
#[cfg(test)]
mod test {}
