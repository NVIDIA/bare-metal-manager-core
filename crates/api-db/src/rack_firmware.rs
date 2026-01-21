/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Error::RowNotFound;
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, PgConnection, Row};

use crate::{DatabaseError, DatabaseResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RackFirmware {
    pub id: String,
    pub config: Json<serde_json::Value>,
    pub available: bool,
    pub parsed_components: Option<Json<serde_json::Value>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for RackFirmware {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(RackFirmware {
            id: row.try_get("id")?,
            config: row.try_get("config")?,
            available: row.try_get("available")?,
            parsed_components: row.try_get("parsed_components")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}
impl From<&RackFirmware> for rpc::forge::RackFirmware {
    fn from(db: &RackFirmware) -> Self {
        let parsed_components = db
            .parsed_components
            .as_ref()
            .map(|p| p.0.to_string())
            .unwrap_or_else(|| "{}".to_string());

        rpc::forge::RackFirmware {
            id: db.id.clone(),
            config_json: db.config.0.to_string(),
            available: db.available,
            created: db.created.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated: db.updated.format("%Y-%m-%d %H:%M:%S").to_string(),
            parsed_components,
        }
    }
}

impl RackFirmware {
    /// Create a new Rack firmware configuration
    pub async fn create(
        txn: &mut PgConnection,
        id: &str,
        config: serde_json::Value,
        parsed_components: Option<serde_json::Value>,
    ) -> DatabaseResult<Self> {
        let query = "INSERT INTO rack_firmware (id, config, parsed_components) VALUES ($1, $2::jsonb, $3::jsonb) RETURNING *";

        sqlx::query_as(query)
            .bind(id)
            .bind(Json(config))
            .bind(parsed_components.map(Json))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))
    }

    /// Find a Rack firmware configuration by ID
    pub async fn find_by_id(txn: &mut PgConnection, id: &str) -> DatabaseResult<Self> {
        let query = "SELECT * FROM rack_firmware WHERE id = $1";
        let ret = sqlx::query_as(query).bind(id).fetch_one(txn).await;
        ret.map_err(|e| match e {
            RowNotFound => DatabaseError::NotFoundError {
                kind: "rack firmware",
                id: format!("{id:?}"),
            },
            _ => DatabaseError::query(query, e),
        })
    }

    /// List all Rack firmware configurations
    pub async fn list_all(
        txn: &mut PgConnection,
        only_available: bool,
    ) -> DatabaseResult<Vec<Self>> {
        let query = if only_available {
            "SELECT * FROM rack_firmware WHERE available = true ORDER BY created DESC"
        } else {
            "SELECT * FROM rack_firmware ORDER BY created DESC"
        };

        sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    /// Update the configuration
    #[allow(dead_code)]
    pub async fn update_config(
        txn: &mut PgConnection,
        id: &str,
        config: serde_json::Value,
    ) -> DatabaseResult<Self> {
        let query = "UPDATE rack_firmware SET config = $2::jsonb, updated = NOW() WHERE id = $1 RETURNING *";

        sqlx::query_as(query)
            .bind(id)
            .bind(Json(config))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))
    }

    /// Update the available flag
    #[allow(dead_code)]
    pub async fn set_available(
        txn: &mut PgConnection,
        id: &str,
        available: bool,
    ) -> DatabaseResult<Self> {
        let query =
            "UPDATE rack_firmware SET available = $2, updated = NOW() WHERE id = $1 RETURNING *";

        sqlx::query_as(query)
            .bind(id)
            .bind(available)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))
    }

    /// Delete a Rack firmware configuration
    pub async fn delete(txn: &mut PgConnection, id: &str) -> DatabaseResult<()> {
        let query = "DELETE FROM rack_firmware WHERE id = $1 RETURNING id";

        sqlx::query_as::<_, (String,)>(query)
            .bind(id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))?;

        Ok(())
    }
}
