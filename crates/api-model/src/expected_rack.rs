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

use std::collections::HashMap;

use carbide_uuid::rack::{RackId, RackProfileId};
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::{Metadata, default_metadata_for_deserializer};

/// ExpectedRack represents a rack that has been declared and is expected to
/// be fully populated with compute trays, switches, and power shelves. The
/// rack_profile_id references a RackProfile in the Carbide config file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedRack {
    /// rack_id is the rack identifier, which comes from the DCIM.
    pub rack_id: RackId,

    /// rack_profile_id is the identifier of the rack profile (e.g. "NVL72").
    /// This maps to a RackProfile in the Carbide config file, which defines
    /// the rack hardware type, topology, and rack capabilities.
    pub rack_profile_id: RackProfileId,

    /// User-defined metadata for the rack. Physical-chassis and
    /// physical-location attributes are recorded as well-known label keys
    /// on this Metadata (see api-model::rack for the well-known keys).
    #[serde(default = "default_metadata_for_deserializer")]
    pub metadata: Metadata,
}

impl<'r> FromRow<'r, PgRow> for ExpectedRack {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        Ok(ExpectedRack {
            rack_id: row.try_get("rack_id")?,
            rack_profile_id: row.try_get("rack_profile_id")?,
            metadata,
        })
    }
}
