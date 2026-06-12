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
use std::net::IpAddr;

use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use mac_address::MacAddress;
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::metadata::{Metadata, default_metadata_for_deserializer};

#[derive(Default, Clone, Deserialize)] // Do not add debug here, it contains passwords.
#[serde(default)]
pub struct ExpectedSwitch {
    #[serde(default)]
    pub expected_switch_id: Option<Uuid>,
    pub bmc_mac_address: MacAddress,
    #[serde(default)]
    pub nvos_mac_addresses: Vec<MacAddress>,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
    pub nvos_username: Option<String>,
    pub nvos_password: Option<String>,
    #[serde(default)]
    pub bmc_ip_address: Option<IpAddr>,
    /// Static IP reservation for the single wired NVOS port. Only meaningful
    /// when `nvos_mac_addresses` has exactly one entry; handlers reject this
    /// being set otherwise so the (mac, ip) pairing stays unambiguous.
    #[serde(default)]
    pub nvos_ip_address: Option<IpAddr>,
    #[serde(default = "default_metadata_for_deserializer")]
    pub metadata: Metadata,
    pub rack_id: Option<RackId>,
    /// When true, site-explorer skips BMC password rotation and stores the
    /// factory-default credentials in Vault as-is.
    #[serde(default)]
    pub bmc_retain_credentials: Option<bool>,
}

impl<'r> FromRow<'r, PgRow> for ExpectedSwitch {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        let nvos_mac_addresses: Vec<MacAddress> =
            row.try_get("nvos_mac_addresses").unwrap_or_default();

        Ok(ExpectedSwitch {
            expected_switch_id: row.try_get("expected_switch_id")?,
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            nvos_mac_addresses,
            bmc_username: row.try_get("bmc_username")?,
            serial_number: row.try_get("serial_number")?,
            bmc_password: row.try_get("bmc_password")?,
            nvos_username: row.try_get("nvos_username")?,
            nvos_password: row.try_get("nvos_password")?,
            bmc_ip_address: row.try_get("bmc_ip_address").ok(),
            nvos_ip_address: row.try_get("nvos_ip_address").ok(),
            metadata,
            rack_id: row.try_get("rack_id")?,
            bmc_retain_credentials: row.try_get("bmc_retain_credentials")?,
        })
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedSwitch {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_switches table
    pub switch_id: Option<SwitchId>, // The switch
    pub expected_switch_id: Option<Uuid>, // The expected switch ID
    pub address: Option<IpAddr>,     // The explored BMC endpoint IP
    pub rack_id: Option<RackId>,     // The rack this switch belongs to
}

/// A request to identify an ExpectedSwitch by either ID or MAC address.
#[derive(Debug, Clone)]
pub struct ExpectedSwitchRequest {
    pub expected_switch_id: Option<Uuid>,
    pub bmc_mac_address: Option<MacAddress>,
}
