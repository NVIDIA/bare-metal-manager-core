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

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::rack::RackId;
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::{Metadata, default_metadata_for_deserializer};

/// ExpectedRack represents a rack that has been declared and is expected to
/// be fully populated with compute trays, switches, and power shelves. The
/// rack_type determines how many of each node type to expect.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedRack {
    /// rack_id is the rack identifier, which comes from the DCIM.
    /// This is the same rack_id that expected machines, switches,
    /// and power shelves reference.
    pub rack_id: RackId,

    /// rack_type is the type of rack (e.g. if it's a 72x1, 36x1, etc), which
    /// determines the expected number of compute trays, switches, and power
    /// shelves.
    ///
    /// TODO(chet): This must match a key in the rack_types config for now in
    /// our initial implementation, but it may make better sense for the entire
    /// RackTypeConfig to be shoved in here instead in the case of a DCIM
    /// feeding us an expected rack config.
    pub rack_type: String,

    /// User-defined metadata for the rack.
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
            rack_type: row.try_get("rack_type")?,
            metadata,
        })
    }
}

impl From<ExpectedRack> for rpc::forge::ExpectedRack {
    fn from(expected_rack: ExpectedRack) -> Self {
        rpc::forge::ExpectedRack {
            rack_id: Some(expected_rack.rack_id),
            rack_type: expected_rack.rack_type,
            metadata: Some(expected_rack.metadata.into()),
        }
    }
}

impl TryFrom<rpc::forge::ExpectedRack> for ExpectedRack {
    type Error = RpcDataConversionError;

    fn try_from(rpc: rpc::forge::ExpectedRack) -> Result<Self, Self::Error> {
        let rack_id = rpc
            .rack_id
            .ok_or(RpcDataConversionError::MissingArgument("rack_id"))?;
        if rpc.rack_type.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "rack_type is required".to_string(),
            ));
        }
        let metadata = Metadata::try_from(rpc.metadata.unwrap_or_default())?;

        Ok(ExpectedRack {
            rack_id,
            rack_type: rpc.rack_type,
            metadata,
        })
    }
}
