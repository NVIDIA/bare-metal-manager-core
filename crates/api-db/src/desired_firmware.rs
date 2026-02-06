/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
