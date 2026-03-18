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
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, Row};

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

/// A record of a rack firmware apply operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RackFirmwareApplyHistoryRecord {
    pub firmware_id: String,
    pub rack_id: String,
    pub firmware_type: String,
    pub applied_at: DateTime<Utc>,
    pub firmware_available: bool,
}

impl From<RackFirmwareApplyHistoryRecord> for rpc::forge::RackFirmwareHistoryRecord {
    fn from(record: RackFirmwareApplyHistoryRecord) -> Self {
        rpc::forge::RackFirmwareHistoryRecord {
            firmware_id: record.firmware_id,
            rack_id: record.rack_id,
            firmware_type: record.firmware_type,
            applied_at: record.applied_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            firmware_available: record.firmware_available,
        }
    }
}
