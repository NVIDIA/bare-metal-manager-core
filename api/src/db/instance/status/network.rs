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

use sqlx::{Postgres, Transaction};

use crate::{
    db::DatabaseError, model::instance::status::network::InstanceNetworkStatusObservation,
};

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

    let query =
        "UPDATE instances SET network_status_observation=$1::json where id = $2::uuid returning id";
    let (_,): (uuid::Uuid,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(status))
        .bind(instance_id)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}
