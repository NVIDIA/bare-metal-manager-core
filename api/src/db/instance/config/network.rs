/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::model::{config_version::Versioned, instance::config::network::InstanceNetworkConfig};

/// Loads the network configuration for an instance
///
/// Note: This might later be merged with `Instance` if everything works
/// together better
pub async fn load_instance_network_config(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
) -> Result<Option<Versioned<InstanceNetworkConfig>>, sqlx::Error> {
    impl<'r> sqlx::FromRow<'r, PgRow> for Versioned<InstanceNetworkConfig> {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let network_config_version_str: &str = row.try_get("network_config_version")?;
            let network_config_version = network_config_version_str
                .parse()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

            let network_config: sqlx::types::Json<InstanceNetworkConfig> =
                row.try_get("network_config")?;

            Ok(Versioned::new(network_config.0, network_config_version))
        }
    }

    sqlx::query_as(
        "SELECT network_config, network_config_version FROM instances where id = $1::uuid",
    )
    .bind(&instance_id)
    .fetch_optional(&mut *txn)
    .await
}
