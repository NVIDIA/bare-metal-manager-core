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

use crate::{
    db::DatabaseError, model::instance::status::network::InstanceNetworkStatusObservation,
};

/// Loads the latest network status observation for an instance
///
/// The result will be `Ok(None)` if no network status has ever been reported for this
/// instance.
pub async fn load_instance_network_status_observation(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
) -> Result<Option<InstanceNetworkStatusObservation>, DatabaseError> {
    /// This is wrapper to allow implementing FromRow on the Option
    #[derive(serde::Deserialize)]
    struct OptionalObservation(Option<InstanceNetworkStatusObservation>);

    impl<'r> sqlx::FromRow<'r, PgRow> for OptionalObservation {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let network_status_observation: sqlx::types::Json<OptionalObservation> =
                row.try_get("network_status_observation")?;
            Ok(network_status_observation.0)
        }
    }

    let query = "SELECT network_status_observation FROM instances where id = $1::uuid";
    let observation: OptionalObservation = sqlx::query_as(query)
        .bind(instance_id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(observation.0)
}

/// Updates the latest network status observation for an instance
pub async fn update_instance_network_status_observation(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
    status: &InstanceNetworkStatusObservation,
) -> Result<(), DatabaseError> {
    // TODO: This might rather belong into the API layer
    // We will move move it there once that code is in place
    status.validate().map_err(|e| {
        DatabaseError::new(
            file!(),
            line!(),
            "ioerror",
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        )
    })?;

    /*
        map_err(|e| {
        sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    */

    let query =
        "UPDATE instances SET network_status_observation=$1::json where id = $2::uuid returning id";
    let (_,): (uuid::Uuid,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(status))
        .bind(instance_id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}
