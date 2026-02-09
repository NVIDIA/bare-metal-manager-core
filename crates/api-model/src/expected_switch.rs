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

use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use mac_address::MacAddress;
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;

fn default_metadata_for_deserializer() -> Metadata {
    Metadata {
        name: "".to_string(),
        description: "".to_string(),
        labels: HashMap::default(),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedSwitch {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
    pub nvos_username: Option<String>,
    pub nvos_password: Option<String>,
    #[serde(default = "default_metadata_for_deserializer")]
    pub metadata: Metadata,
    pub rack_id: Option<RackId>,
}

impl<'r> FromRow<'r, PgRow> for ExpectedSwitch {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        Ok(ExpectedSwitch {
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            bmc_username: row.try_get("bmc_username")?,
            serial_number: row.try_get("serial_number")?,
            bmc_password: row.try_get("bmc_password")?,
            nvos_username: row.try_get("nvos_username")?,
            nvos_password: row.try_get("nvos_password")?,
            metadata,
            rack_id: row.try_get("rack_id")?,
        })
    }
}

impl From<ExpectedSwitch> for rpc::forge::ExpectedSwitch {
    fn from(expected_switch: ExpectedSwitch) -> Self {
        rpc::forge::ExpectedSwitch {
            bmc_mac_address: expected_switch.bmc_mac_address.to_string(),
            bmc_username: expected_switch.bmc_username,
            bmc_password: expected_switch.bmc_password,
            switch_serial_number: expected_switch.serial_number,
            nvos_username: expected_switch.nvos_username,
            nvos_password: expected_switch.nvos_password,
            metadata: Some(expected_switch.metadata.into()),
            rack_id: expected_switch.rack_id,
        }
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedSwitch {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_switches table
    pub switch_id: Option<SwitchId>, // The switch
}

impl From<LinkedExpectedSwitch> for rpc::forge::LinkedExpectedSwitch {
    fn from(l: LinkedExpectedSwitch) -> rpc::forge::LinkedExpectedSwitch {
        rpc::forge::LinkedExpectedSwitch {
            switch_serial_number: l.serial_number,
            bmc_mac_address: l.bmc_mac_address.to_string(),
            switch_id: l.switch_id,
        }
    }
}
