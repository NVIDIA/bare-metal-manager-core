use ::rpc::forge as rpc;
use version_compare::Cmp;

use crate::{CarbideError, CarbideResult};
use eyre::{Report, eyre};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use std::net::IpAddr;

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
    type Error = CarbideError;
    fn try_from(value: rpc::BmcInfo) -> CarbideResult<Self> {
        let mac: Option<MacAddress> = if let Some(mac_address) = value.mac {
            Some(mac_address.parse()?)
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
