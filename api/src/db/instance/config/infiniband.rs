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

use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

use crate::db::DatabaseError;
use crate::model::{
    config_version::Versioned, instance::config::infiniband::InstanceInfinibandConfig,
};

/// Loads the infiniband configuration for an instance
///
/// Note: This might later be merged with `Instance` if everything works
/// together better
pub async fn load_instance_infiniband_config(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
) -> Result<Versioned<InstanceInfinibandConfig>, DatabaseError> {
    impl<'r> sqlx::FromRow<'r, PgRow> for Versioned<InstanceInfinibandConfig> {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let ib_config_version_str: &str = row.try_get("ib_config_version")?;
            let ib_config_version = ib_config_version_str
                .parse()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

            let ib_config: sqlx::types::Json<InstanceInfinibandConfig> =
                row.try_get("ib_config")?;

            Ok(Versioned::new(ib_config.0, ib_config_version))
        }
    }

    let query = "SELECT ib_config, ib_config_version FROM instances where id = $1::uuid";
    sqlx::query_as(query)
        .bind(instance_id)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}
