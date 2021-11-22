use crate::CarbideResult;
use mac_address::MacAddress;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use std::net::{Ipv4Addr, Ipv6Addr};

use rpc::v0 as rpc;

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug)]
pub struct DhcpRecord {
    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,
    fqdn: String,
    subdomain: String,
    mtu: i32,

    address_ipv4: Option<AddressAssignmentV4>,
    address_ipv6: Option<AddressAssignmentV6>,
}

#[derive(Debug)]
pub struct AddressAssignmentV4 {
    address: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    mac_address: MacAddress,
    mask: Ipv4Addr,
}

pub type Duid = String;

#[derive(Debug)]
pub struct AddressAssignmentV6 {
    duid: Duid,
    address: Ipv6Addr,
}

impl<'r> sqlx::FromRow<'r, PgRow> for DhcpRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let gateway_ipv4 = if let Some(gateway_ipv4) = row.try_get("gateway_ipv4")? {
            Some(
                crate::network_to_host_ipv4(gateway_ipv4)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))?,
            )
        } else {
            None
        };

        let address_ipv4 = if let Some(address_ipv4) = row.try_get("address_ipv4")? {
            Some(
                crate::network_to_host_ipv4(address_ipv4)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))
                    .map(|address| AddressAssignmentV4 {
                        address,
                        mac_address: row.try_get("mac_address").unwrap(),
                        gateway: gateway_ipv4,
                        mask: "255.255.255.0".parse().unwrap(),
                    })?,
            )
        } else {
            None
        };

        let address_ipv6 = if let Some(address_ipv6) = row.try_get("address_ipv6")? {
            Some(
                crate::network_to_host_ipv6(address_ipv6)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))
                    .map(|address| AddressAssignmentV6 {
                        address,
                        duid: String::new(),
                    })?,
            )
        } else {
            None
        };

        Ok(DhcpRecord {
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            address_ipv4,
            address_ipv6,
            fqdn: row.try_get("fqdn")?,
            subdomain: row.try_get("subdomain")?,
            mtu: row.try_get("mtu")?,
        })
    }
}

impl From<AddressAssignmentV4> for rpc::AddressAssignmentV4 {
    fn from(assignment: AddressAssignmentV4) -> Self {
        Self {
            mac_address: assignment.mac_address.to_string(),
            address: assignment.address.to_string(),
            gateway: assignment.gateway.map(|gw| gw.to_string()),
            mask: assignment.mask.to_string(),
        }
    }
}

impl From<AddressAssignmentV6> for rpc::AddressAssignmentV6 {
    fn from(assignment: AddressAssignmentV6) -> Self {
        Self {
            address: assignment.address.to_string(),
            duid: assignment.duid,
        }
    }
}

impl From<DhcpRecord> for rpc::DhcpRecord {
    fn from(record: DhcpRecord) -> Self {
        Self {
            machine_id: Some(record.machine_id.into()),
            segment_id: Some(record.segment_id.into()),
            subdomain: record.subdomain,
            fqdn: record.fqdn,
            address_ipv4: record.address_ipv4.map(|addr| addr.into()),
            address_ipv6: record.address_ipv6.map(|addr| addr.into()),
        }
    }
}

impl DhcpRecord {
    pub async fn find_by_id_ipv4(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: &MacAddress,
        segment_id: &uuid::Uuid,
    ) -> CarbideResult<DhcpRecord> {
        Ok(sqlx::query_as("SELECT * FROM machine_dhcp_responses WHERE mac_address = $1::macaddr AND segment_id = $2::uuid")
            .bind(mac_address)
            .bind(segment_id)
            .fetch_one(&mut *txn).await?)
    }

    #[allow(unused_variables)]
    pub async fn find_by_id_ipv6(
        txn: &mut Transaction<'_, Postgres>,
        duid: String,
        segment_id: &uuid::Uuid,
    ) -> CarbideResult<DhcpRecord> {
        unimplemented!();
    }
}
