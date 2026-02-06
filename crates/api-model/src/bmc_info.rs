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
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use eyre::{Report, eyre};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use version_compare::Cmp;

use crate::errors::{ModelError, ModelResult};
// TODO(chet): Once SocketAddr::parse_ascii is no longer an experimental
// feature, it would be good to parse bmc_info.ip to verify it's a valid IP
// address.

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BmcInfo {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub mac: Option<MacAddress>,
    pub version: Option<String>,
    pub firmware_version: Option<String>,
}

impl BmcInfo {
    pub fn supports_bfb_install(&self) -> bool {
        self.firmware_version.as_ref().is_some_and(|v| {
            version_compare::compare_to(v.to_lowercase().replace("bf-", ""), "24.10", Cmp::Ge)
                .is_ok_and(|r| r)
        })
    }
}

impl<'r> FromRow<'r, PgRow> for BmcInfo {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let bmc_info: String = row.try_get("bmc_info")?;
        serde_json::from_str(&bmc_info).map_err(|e| sqlx::Error::ColumnDecode {
            index: "bmc_info".to_owned(),
            source: e.into(),
        })
    }
}

impl TryFrom<rpc::BmcInfo> for BmcInfo {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::BmcInfo) -> Result<Self, RpcDataConversionError> {
        let mac: Option<MacAddress> = if let Some(mac_address) = value.mac {
            Some(
                mac_address
                    .parse()
                    .map_err(|_| RpcDataConversionError::InvalidMacAddress(mac_address))?,
            )
        } else {
            None
        };

        Ok(BmcInfo {
            ip: value.ip,
            port: value.port.map(|p| p as u16),
            mac,
            version: value.version,
            firmware_version: value.firmware_version,
        })
    }
}

impl BmcInfo {
    pub fn ip_addr(&self) -> Result<IpAddr, Report> {
        self.ip
            .as_ref()
            .ok_or(eyre! {"Missing BMC address"})?
            .parse()
            .map_err(|e| {
                eyre! {"Bad address {:?} {e}", self.ip }
            })
    }
}

impl From<BmcInfo> for rpc::BmcInfo {
    fn from(value: BmcInfo) -> Self {
        rpc::BmcInfo {
            ip: value.ip,
            port: value.port.map(|p| p as u32),
            mac: value.mac.map(|mac| mac.to_string()),
            version: value.version,
            firmware_version: value.firmware_version,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "user_roles")]
#[sqlx(rename_all = "lowercase")]
pub enum UserRoles {
    User,
    Administrator,
    Operator,
    Noaccess,
}

impl Display for UserRoles {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            UserRoles::User => "user",
            UserRoles::Administrator => "administrator",
            UserRoles::Operator => "operator",
            UserRoles::Noaccess => "noaccess",
        };

        write!(f, "{string}")
    }
}

impl From<rpc::UserRoles> for UserRoles {
    fn from(action: rpc::UserRoles) -> Self {
        match action {
            rpc::UserRoles::User => UserRoles::User,
            rpc::UserRoles::Administrator => UserRoles::Administrator,
            rpc::UserRoles::Operator => UserRoles::Operator,
            rpc::UserRoles::Noaccess => UserRoles::Noaccess,
        }
    }
}

impl From<UserRoles> for rpc::UserRoles {
    fn from(action: UserRoles) -> Self {
        match action {
            UserRoles::User => rpc::UserRoles::User,
            UserRoles::Administrator => rpc::UserRoles::Administrator,
            UserRoles::Operator => rpc::UserRoles::Operator,
            UserRoles::Noaccess => rpc::UserRoles::Noaccess,
        }
    }
}

impl FromStr for UserRoles {
    type Err = ModelError;

    fn from_str(input: &str) -> ModelResult<Self> {
        match input {
            "user" => Ok(UserRoles::User),
            "administrator" => Ok(UserRoles::Administrator),
            "operator" => Ok(UserRoles::Operator),
            "noaccess" => Ok(UserRoles::Noaccess),
            x => Err(ModelError::DatabaseTypeConversionError(format!(
                "Unknown role found in database: {x}"
            ))),
        }
    }
}
