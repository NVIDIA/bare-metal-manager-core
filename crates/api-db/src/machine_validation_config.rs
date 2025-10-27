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
use config_version::ConfigVersion;
use model::machine_validation::MachineValidationExternalConfig;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

pub async fn find_config_by_name(
    txn: &mut PgConnection,
    name: &str,
) -> DatabaseResult<MachineValidationExternalConfig> {
    let query = "SELECT * FROM machine_validation_external_config WHERE name=$1";
    match sqlx::query_as(query).bind(name).fetch_one(txn).await {
        Ok(val) => Ok(val),
        Err(_) => Err(DatabaseError::NotFoundError {
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
) -> DatabaseResult<()> {
    let query = "INSERT INTO machine_validation_external_config (name, description, config, version) VALUES ($1, $2, $3, $4) RETURNING name";

    let _: () = sqlx::query_as(query)
        .bind(name)
        .bind(description)
        .bind(config.as_slice())
        .bind(ConfigVersion::initial())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

async fn update(
    txn: &mut PgConnection,
    name: &str,
    config: &Vec<u8>,
    next_version: ConfigVersion,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_validation_external_config SET config=$2, version=$3 WHERE name=$1 RETURNING name";

    let _: () = sqlx::query_as(query)
        .bind(name)
        .bind(config.as_slice())
        .bind(next_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn create_or_update(
    txn: &mut PgConnection,
    name: &str,
    description: &str,
    data: &Vec<u8>,
) -> DatabaseResult<()> {
    match find_config_by_name(txn, name).await {
        Ok(config) => update(txn, name, data, config.version.increment()).await?,
        Err(_) => save(txn, name, description, data).await?,
    };
    Ok(())
}

pub async fn find_configs(
    txn: &mut PgConnection,
) -> DatabaseResult<Vec<MachineValidationExternalConfig>> {
    let query = "SELECT * FROM machine_validation_external_config";

    let names = sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(names)
}

pub async fn remove_config(
    txn: &mut PgConnection,
    name: &str,
) -> DatabaseResult<MachineValidationExternalConfig> {
    let query = "DELETE FROM machine_validation_external_config WHERE name=$1 RETURNING *";
    match sqlx::query_as(query).bind(name).fetch_one(txn).await {
        Ok(val) => Ok(val),
        Err(_) => Err(DatabaseError::NotFoundError {
            kind: "machine_validation_external_config",
            id: name.to_owned(),
        }),
    }
}
