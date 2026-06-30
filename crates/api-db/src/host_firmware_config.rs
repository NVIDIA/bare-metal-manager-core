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

use chrono::{DateTime, Utc};
use model::firmware::Firmware;
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::{DatabaseError, DatabaseResult};

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct HostFirmwareConfigRow {
    pub vendor: String,
    pub model: String,
    pub config: Json<Firmware>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl HostFirmwareConfigRow {
    pub fn into_config(self) -> Firmware {
        self.config.0
    }
}

/// Serializes read-merge-write operations for one vendor/model key.
///
/// This locks even when the row does not exist yet, so concurrent creates for
/// the same key merge in request order instead of replacing each other.
pub async fn lock_for_update(
    txn: &mut PgConnection,
    vendor: &str,
    model: &str,
) -> DatabaseResult<()> {
    let query = r#"
        SELECT pg_advisory_xact_lock(
            hashtextextended('host_firmware_config:' || $1 || ':' || lower($2), 0)
        )
    "#;

    sqlx::query(query)
        .bind(vendor)
        .bind(model)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn upsert(
    txn: &mut PgConnection,
    config: &Firmware,
) -> DatabaseResult<HostFirmwareConfigRow> {
    let query = r#"
        INSERT INTO host_firmware_config (vendor, model, config)
        VALUES ($1, $2, $3)
        ON CONFLICT (vendor, lower(model))
        DO UPDATE SET
            model = EXCLUDED.model,
            config = EXCLUDED.config
        RETURNING vendor, model, config, created_at, updated_at
    "#;

    sqlx::query_as(query)
        .bind(config.vendor.to_pascalcase())
        .bind(&config.model)
        .bind(Json(config.clone()))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get(
    txn: &mut PgConnection,
    vendor: &str,
    model: &str,
) -> DatabaseResult<Option<HostFirmwareConfigRow>> {
    let query = r#"
        SELECT vendor, model, config, created_at, updated_at
        FROM host_firmware_config
        WHERE vendor = $1 AND lower(model) = lower($2)
    "#;

    sqlx::query_as(query)
        .bind(vendor)
        .bind(model)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use model::firmware::{
        Firmware, FirmwareComponent, FirmwareComponentType, FirmwareEntry, FirmwareFileArtifact,
    };
    use regex::Regex;

    fn test_config(version: &str) -> Firmware {
        Firmware {
            vendor: "nvidia".into(),
            model: "DGXH100".to_string(),
            explicit_start_needed: true,
            ordering: vec![FirmwareComponentType::Cx7],
            components: HashMap::from([(
                FirmwareComponentType::Cx7,
                FirmwareComponent {
                    current_version_reported_as: Some(Regex::new("^CX7_[0-9]+$").unwrap()),
                    preingest_upgrade_when_below: None,
                    known_firmware: vec![FirmwareEntry {
                        version: version.to_string(),
                        default: true,
                        files: vec![FirmwareFileArtifact {
                            filename: None,
                            url: Some(format!("https://example.invalid/{version}/fw.bin")),
                            sha256: String::new(),
                        }],
                        ..Default::default()
                    }],
                },
            )]),
        }
    }

    #[crate::sqlx_test]
    async fn upsert_replaces_existing_row(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        let first = super::upsert(&mut txn, &test_config("28.43.2026")).await?;
        let second = super::upsert(&mut txn, &test_config("28.47.2682")).await?;

        assert_eq!(first.vendor, "Nvidia");
        assert_eq!(first.model, "DGXH100");
        assert_eq!(first.created_at, second.created_at);
        assert!(second.updated_at >= first.updated_at);

        let stored = super::get(&mut txn, "Nvidia", "dgxh100")
            .await?
            .expect("stored host firmware config");
        let config = stored.into_config();
        let cx7 = config
            .components
            .get(&FirmwareComponentType::Cx7)
            .expect("cx7 component");
        assert_eq!(cx7.known_firmware[0].version, "28.47.2682");

        Ok(())
    }
}
