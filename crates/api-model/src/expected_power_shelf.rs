/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::net::IpAddr;

use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
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
pub struct ExpectedPowerShelf {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub serial_number: String,
    pub bmc_password: String,
    pub ip_address: Option<IpAddr>,
    #[serde(default = "default_metadata_for_deserializer")]
    pub metadata: Metadata,
    pub rack_id: Option<RackId>,
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
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            bmc_username: row.try_get("bmc_username")?,
            serial_number: row.try_get("serial_number")?,
            bmc_password: row.try_get("bmc_password")?,
            ip_address: row.try_get("ip_address").ok(),
            metadata,
            rack_id: row.try_get("rack_id").ok(),
        })
    }
}

impl From<ExpectedPowerShelf> for rpc::forge::ExpectedPowerShelf {
    fn from(expected_power_shelf: ExpectedPowerShelf) -> Self {
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: expected_power_shelf.bmc_mac_address.to_string(),
            bmc_username: expected_power_shelf.bmc_username,
            bmc_password: expected_power_shelf.bmc_password,
            shelf_serial_number: expected_power_shelf.serial_number,
            ip_address: expected_power_shelf
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            metadata: Some(expected_power_shelf.metadata.into()),
            rack_id: expected_power_shelf.rack_id,
        }
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedPowerShelf {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_power_shelves table
    pub power_shelf_id: Option<PowerShelfId>, // The power shelf
}

impl From<LinkedExpectedPowerShelf> for rpc::forge::LinkedExpectedPowerShelf {
    fn from(l: LinkedExpectedPowerShelf) -> rpc::forge::LinkedExpectedPowerShelf {
        rpc::forge::LinkedExpectedPowerShelf {
            shelf_serial_number: l.serial_number,
            bmc_mac_address: l.bmc_mac_address.to_string(),
            power_shelf_id: l.power_shelf_id,
        }
    }
}
