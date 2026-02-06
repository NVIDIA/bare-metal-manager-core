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

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::metadata::Metadata;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExpectedHostNic {
    pub mac_address: MacAddress,
    // something to help the dhcp code select the right ip subnet, eg: bf3, onboard, cx8, oob, etc.
    pub nic_type: Option<String>,
    pub fixed_ip: Option<String>,
    pub fixed_mask: Option<String>,
    pub fixed_gateway: Option<String>,
}

// Important : new fields for expected machine should be Optional _and_ #[serde(default)],
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedMachine {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub bmc_mac_address: MacAddress,
    #[serde(flatten)]
    pub data: ExpectedMachineData,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExpectedMachineData {
    pub bmc_username: String,
    pub bmc_password: String,
    pub serial_number: String,
    #[serde(default)]
    pub fallback_dpu_serial_numbers: Vec<String>,
    #[serde(default)]
    pub sku_id: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(skip)]
    pub override_id: Option<Uuid>,
    #[serde(default)]
    pub host_nics: Vec<ExpectedHostNic>,
    pub rack_id: Option<RackId>,
    pub default_pause_ingestion_and_poweron: Option<bool>,
    #[serde(default)]
    pub dpf_enabled: bool,
}
// Important : new fields for expected machine (and data) should be optional _and_ serde(default),
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup

impl<'r> FromRow<'r, PgRow> for ExpectedMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        let json: sqlx::types::Json<Vec<ExpectedHostNic>> = row.try_get("host_nics")?;
        let host_nics: Vec<ExpectedHostNic> = json.0;

        Ok(ExpectedMachine {
            id: row.try_get("id")?,
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            data: ExpectedMachineData {
                bmc_username: row.try_get("bmc_username")?,
                serial_number: row.try_get("serial_number")?,
                bmc_password: row.try_get("bmc_password")?,
                fallback_dpu_serial_numbers: row.try_get("fallback_dpu_serial_numbers")?,
                metadata,
                sku_id: row.try_get("sku_id")?,
                override_id: None,
                rack_id: row.try_get("rack_id")?,
                host_nics,
                default_pause_ingestion_and_poweron: row
                    .try_get("default_pause_ingestion_and_poweron")?,
                dpf_enabled: row.try_get("dpf_enabled")?,
            },
        })
    }
}

impl From<ExpectedHostNic> for rpc::forge::ExpectedHostNic {
    fn from(expected_host_nic: ExpectedHostNic) -> Self {
        rpc::forge::ExpectedHostNic {
            mac_address: expected_host_nic.mac_address.to_string(),
            nic_type: expected_host_nic.nic_type,
            fixed_ip: expected_host_nic.fixed_ip,
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: expected_host_nic.fixed_gateway,
        }
    }
}

impl From<rpc::forge::ExpectedHostNic> for ExpectedHostNic {
    fn from(expected_host_nic: rpc::forge::ExpectedHostNic) -> Self {
        ExpectedHostNic {
            mac_address: expected_host_nic.mac_address.parse().unwrap_or_default(),
            nic_type: expected_host_nic.nic_type,
            fixed_ip: expected_host_nic.fixed_ip,
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: expected_host_nic.fixed_gateway,
        }
    }
}

impl From<ExpectedMachine> for rpc::forge::ExpectedMachine {
    fn from(expected_machine: ExpectedMachine) -> Self {
        let host_nics = expected_machine
            .data
            .host_nics
            .iter()
            .map(|x| x.clone().into())
            .collect();
        rpc::forge::ExpectedMachine {
            id: expected_machine.id.map(|u| ::rpc::common::Uuid {
                value: u.to_string(),
            }),
            bmc_mac_address: expected_machine.bmc_mac_address.to_string(),
            bmc_username: expected_machine.data.bmc_username,
            bmc_password: expected_machine.data.bmc_password,
            chassis_serial_number: expected_machine.data.serial_number,
            fallback_dpu_serial_numbers: expected_machine.data.fallback_dpu_serial_numbers,
            metadata: Some(expected_machine.data.metadata.into()),
            sku_id: expected_machine.data.sku_id,
            rack_id: expected_machine.data.rack_id,
            host_nics,
            default_pause_ingestion_and_poweron: expected_machine
                .data
                .default_pause_ingestion_and_poweron,
            dpf_enabled: expected_machine.data.dpf_enabled,
        }
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedMachine {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_machines table
    pub interface_id: Option<MachineInterfaceId>, // from machine_interfaces table
    pub address: Option<String>,     // The explored endpoint
    pub machine_id: Option<MachineId>, // The machine
    pub expected_machine_id: Option<Uuid>, // The expected machine ID
}

impl From<LinkedExpectedMachine> for rpc::forge::LinkedExpectedMachine {
    fn from(m: LinkedExpectedMachine) -> rpc::forge::LinkedExpectedMachine {
        rpc::forge::LinkedExpectedMachine {
            chassis_serial_number: m.serial_number,
            bmc_mac_address: m.bmc_mac_address.to_string(),
            interface_id: m.interface_id.map(|u| u.to_string()),
            explored_endpoint_address: m.address,
            machine_id: m.machine_id,
            expected_machine_id: m.expected_machine_id.map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            }),
        }
    }
}

impl TryFrom<rpc::forge::ExpectedMachine> for ExpectedMachineData {
    type Error = RpcDataConversionError;

    fn try_from(em: rpc::forge::ExpectedMachine) -> Result<Self, Self::Error> {
        Ok(Self {
            bmc_username: em.bmc_username,
            bmc_password: em.bmc_password,
            serial_number: em.chassis_serial_number,
            fallback_dpu_serial_numbers: em.fallback_dpu_serial_numbers,
            sku_id: em.sku_id,
            metadata: metadata_from_request(em.metadata)?,
            override_id: em.id.and_then(|u| Uuid::parse_str(&u.value).ok()),
            host_nics: em.host_nics.into_iter().map(|nic| nic.into()).collect(),
            rack_id: em.rack_id,
            default_pause_ingestion_and_poweron: em.default_pause_ingestion_and_poweron,
            dpf_enabled: em.dpf_enabled,
        })
    }
}

/// If Metadata is retrieved as part of the ExpectedMachine creation, validate and use the Metadata
/// Otherwise assume empty Metadata
fn metadata_from_request(
    opt_metadata: Option<::rpc::forge::Metadata>,
) -> Result<Metadata, RpcDataConversionError> {
    Ok(match opt_metadata {
        None => Metadata {
            name: "".to_string(),
            description: "".to_string(),
            labels: Default::default(),
        },
        Some(m) => {
            // Note that this is unvalidated Metadata. It can contain non-ASCII names
            // and
            let m: Metadata = m.try_into()?;
            m.validate(false)
                .map_err(|e| RpcDataConversionError::InvalidArgument(e.to_string()))?;
            m
        }
    })
}

// default_uuid removed; ids are optional to support legacy rows with NULL ids
