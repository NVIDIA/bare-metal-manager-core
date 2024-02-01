use ::rpc::forge as rpc;

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BmcInfo {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub version: Option<String>,
    pub firmware_version: Option<String>,
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

impl From<rpc::BmcInfo> for BmcInfo {
    fn from(value: rpc::BmcInfo) -> Self {
        BmcInfo {
            ip: value.ip,
            mac: value.mac,
            version: value.version,
            firmware_version: value.firmware_version,
        }
    }
}

impl From<BmcInfo> for rpc::BmcInfo {
    fn from(value: BmcInfo) -> Self {
        rpc::BmcInfo {
            ip: value.ip,
            mac: value.mac,
            version: value.version,
            firmware_version: value.firmware_version,
        }
    }
}
