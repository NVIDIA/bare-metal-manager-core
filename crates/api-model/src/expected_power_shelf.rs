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

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::metadata::{Metadata, default_metadata_for_deserializer};

#[derive(Clone, Default, Deserialize)] // Do not add Debug here. It contains password.
pub struct ExpectedPowerShelf {
    #[serde(default)]
    pub expected_power_shelf_id: Option<Uuid>,
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
    pub bmc_ip_address: Option<IpAddr>,
    #[serde(default = "default_metadata_for_deserializer")]
    pub metadata: Metadata,
    pub rack_id: Option<RackId>,
    /// When true, site-explorer skips BMC password rotation and stores the
    /// factory-default credentials in Vault as-is.
    #[serde(default)]
    pub bmc_retain_credentials: Option<bool>,
}

impl<'r> FromRow<'r, PgRow> for ExpectedPowerShelf {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        Ok(ExpectedPowerShelf {
            expected_power_shelf_id: row.try_get("expected_power_shelf_id")?,
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            bmc_username: row.try_get("bmc_username")?,
            serial_number: row.try_get("serial_number")?,
            bmc_password: row.try_get("bmc_password")?,
            bmc_ip_address: row.try_get("bmc_ip_address").ok(),
            metadata,
            rack_id: row.try_get("rack_id").ok(),
            bmc_retain_credentials: row.try_get("bmc_retain_credentials")?,
        })
    }
}

impl From<ExpectedPowerShelf> for rpc::forge::ExpectedPowerShelf {
    fn from(expected_power_shelf: ExpectedPowerShelf) -> Self {
        rpc::forge::ExpectedPowerShelf {
            expected_power_shelf_id: expected_power_shelf.expected_power_shelf_id.map(|u| {
                ::rpc::common::Uuid {
                    value: u.to_string(),
                }
            }),
            bmc_mac_address: expected_power_shelf.bmc_mac_address.to_string(),
            bmc_username: expected_power_shelf.bmc_username,
            bmc_password: expected_power_shelf.bmc_password,
            shelf_serial_number: expected_power_shelf.serial_number,
            bmc_ip_address: expected_power_shelf
                .bmc_ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            metadata: Some(expected_power_shelf.metadata.into()),
            rack_id: expected_power_shelf.rack_id,
            bmc_retain_credentials: expected_power_shelf.bmc_retain_credentials.filter(|&v| v),
        }
    }
}

impl TryFrom<rpc::forge::ExpectedPowerShelf> for ExpectedPowerShelf {
    type Error = RpcDataConversionError;

    fn try_from(rpc: rpc::forge::ExpectedPowerShelf) -> Result<Self, Self::Error> {
        let bmc_mac_address = MacAddress::try_from(rpc.bmc_mac_address.as_str())
            .map_err(|_| RpcDataConversionError::InvalidMacAddress(rpc.bmc_mac_address.clone()))?;
        let expected_power_shelf_id = rpc
            .expected_power_shelf_id
            .map(|u| {
                Uuid::parse_str(&u.value)
                    .map_err(|_| RpcDataConversionError::InvalidArgument(u.value))
            })
            .transpose()?;
        let bmc_ip_address = if rpc.bmc_ip_address.is_empty() {
            None
        } else {
            rpc.bmc_ip_address.parse().ok()
        };
        let metadata = Metadata::try_from(rpc.metadata.unwrap_or_default())?;

        Ok(ExpectedPowerShelf {
            expected_power_shelf_id,
            bmc_mac_address,
            bmc_username: rpc.bmc_username,
            bmc_password: rpc.bmc_password,
            serial_number: rpc.shelf_serial_number,
            bmc_ip_address,
            metadata,
            rack_id: rpc.rack_id,
            bmc_retain_credentials: rpc.bmc_retain_credentials,
        })
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedPowerShelf {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_power_shelves table
    pub power_shelf_id: Option<PowerShelfId>, // The power shelf
    pub expected_power_shelf_id: Option<Uuid>, // The expected power shelf ID
    pub address: Option<String>,     // The explored BMC endpoint IP
    pub rack_id: Option<RackId>,     // The rack this power shelf belongs to
}

/// A request to identify an ExpectedPowerShelf by either ID or MAC address.
#[derive(Debug, Clone)]
pub struct ExpectedPowerShelfRequest {
    pub expected_power_shelf_id: Option<Uuid>,
    pub bmc_mac_address: Option<MacAddress>,
}

impl TryFrom<rpc::forge::ExpectedPowerShelfRequest> for ExpectedPowerShelfRequest {
    type Error = RpcDataConversionError;

    fn try_from(rpc: rpc::forge::ExpectedPowerShelfRequest) -> Result<Self, Self::Error> {
        let expected_power_shelf_id = rpc
            .expected_power_shelf_id
            .map(|u| {
                Uuid::parse_str(&u.value)
                    .map_err(|_| RpcDataConversionError::InvalidArgument(u.value))
            })
            .transpose()?;
        let bmc_mac_address = if rpc.bmc_mac_address.is_empty() {
            None
        } else {
            Some(
                MacAddress::try_from(rpc.bmc_mac_address.as_str())
                    .map_err(|_| RpcDataConversionError::InvalidMacAddress(rpc.bmc_mac_address))?,
            )
        };

        Ok(ExpectedPowerShelfRequest {
            expected_power_shelf_id,
            bmc_mac_address,
        })
    }
}

impl From<LinkedExpectedPowerShelf> for rpc::forge::LinkedExpectedPowerShelf {
    fn from(l: LinkedExpectedPowerShelf) -> rpc::forge::LinkedExpectedPowerShelf {
        rpc::forge::LinkedExpectedPowerShelf {
            shelf_serial_number: l.serial_number,
            bmc_mac_address: l.bmc_mac_address.to_string(),
            power_shelf_id: l.power_shelf_id,
            expected_power_shelf_id: l.expected_power_shelf_id.map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            }),
            explored_endpoint_address: l.address,
            rack_id: l.rack_id,
        }
    }
}
