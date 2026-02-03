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

use model::firmware::{DesiredFirmwareVersions, Firmware};
use sqlx::PgConnection;

use super::DatabaseError;

/// snapshot_desired_firmware will replace the desired_firmware table with one matching the given Firmware models
pub async fn snapshot_desired_firmware(
    txn: &mut PgConnection,
    models: &[Firmware],
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM desired_firmware";
    sqlx::query(query)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    for model in models {
        snapshot_desired_firmware_for_model(&mut *txn, model).await?;
    }

    Ok(())
}

async fn snapshot_desired_firmware_for_model(
    txn: &mut PgConnection,
    model: &Firmware,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO desired_firmware (vendor, model, versions, explicit_update_start_needed) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING";

    let mut model = model.clone();
    model.components = model
        .components
        .iter()
        .filter_map(|(k, v)| {
            if v.known_firmware.is_empty() {
                None
            } else {
                Some((*k, v.clone()))
            }
        })
        .collect();
    if model.components.is_empty() {
        // Nothing is defined - do not add to the table.
        return Ok(());
    }

    sqlx::query(query)
        .bind(model.vendor.to_pascalcase())
        .bind(&model.model)
        .bind(sqlx::types::Json(DesiredFirmwareVersions::from(
            model.clone(),
        )))
        .bind(model.explicit_start_needed)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
