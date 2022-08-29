//!
//! Machine - represents a database-backed Machine object
//!
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::{FromRow, Postgres, Row, Transaction};
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::CarbideResult;

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct DpuMachine {
    _machine_id: uuid::Uuid,

    _vpc_leaf_id: uuid::Uuid,

    _machine_interface_id: uuid::Uuid,

    _mac_address: MacAddress,

    address: IpNetwork,

    _hostname: String,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for DpuMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DpuMachine {
            _machine_id: row.try_get("machine_id")?,
            _vpc_leaf_id: row.try_get("vpc_leaf_id")?,
            _machine_interface_id: row.try_get("machine_interfaces_id")?,
            _mac_address: row.try_get("mac_address")?,
            address: row.try_get("address")?,
            _hostname: row.try_get("hostname")?,
        })
    }
}

impl DpuMachine {
    pub fn _vpc_leaf_id(&self) -> &Uuid {
        &self._vpc_leaf_id
    }

    pub fn _machine_id(&self) -> &Uuid {
        &self._machine_id
    }

    pub fn _machine_interface_id(&self) -> &Uuid {
        &self._machine_id
    }

    pub fn _mac_address(&self) -> &MacAddress {
        &self._mac_address
    }

    pub fn address(&self) -> &IpNetwork {
        &self.address
    }

    pub fn _hostname(&self) -> &str {
        &self._hostname
    }

    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT * FROM dpu_machines WHERE machine_id = $1::uuid")
                .bind(&machine_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}

#[cfg(test)]
mod test {}
