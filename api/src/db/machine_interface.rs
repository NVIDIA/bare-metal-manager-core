use super::{AddressSelectionStrategy, Machine, NetworkSegment};
use crate::{CarbideError, CarbideResult};
use eui48::MacAddress;
use itertools::Itertools;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_postgres::Transaction;

use rpc::v0 as rpc;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "prevent_duplicate_mac_for_network";

#[derive(Debug)]
pub struct MachineInterface {
    id: uuid::Uuid,

    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,

    mac_address: MacAddress,

    address_ipv4: Option<Ipv4Addr>,
    address_ipv6: Option<Ipv6Addr>,
}

impl From<tokio_postgres::Row> for MachineInterface {
    fn from(row: tokio_postgres::Row) -> Self {
        let id: uuid::Uuid = row.get("id");

        let address_ipv4 = match row.get("address_ipv4") {
            Some(IpAddr::V4(x)) => Some(Ipv4Addr::from(x)),
            Some(IpAddr::V6(_)) => panic!(
                "Found an IPv6 address in the address_ipv4 field for machine {}",
                &id
            ),
            None => None,
        };

        let address_ipv6 = match row.get("address_ipv6") {
            Some(IpAddr::V6(x)) => Some(Ipv6Addr::from(x)),
            Some(IpAddr::V4(_)) => panic!(
                "Found an IPv4 address in the address_ipv4 field for machine {}",
                &id
            ),
            None => None,
        };

        Self {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            segment_id: row.get("segment_id"),
            mac_address: row.get("mac_address"),

            address_ipv4,
            address_ipv6,
        }
    }
}

impl From<MachineInterface> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterface) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            machine_id: Some(machine_interface.machine_id.into()),
            segment_id: Some(machine_interface.segment_id.into()),

            mac_address: machine_interface
                .mac_address
                .to_string(eui48::MacAddressFormat::HexString),
            address_ipv4: machine_interface.address_ipv4.map(|a| a.to_string()),
            address_ipv6: machine_interface.address_ipv6.map(|a| a.to_string()),
        }
    }
}

impl MachineInterface {
    pub async fn find_by_mac_address(
        txn: &Transaction<'_>,
        macaddr: MacAddress,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(txn
            .query(
                "SELECT * FROM machine_interfaces mi WHERE mi.mac_address = $1::macaddr",
                &[&macaddr],
            )
            .await?
            .into_iter()
            .map(MachineInterface::from)
            .collect::<Vec<MachineInterface>>())
    }

    pub async fn find_by_network_segment(
        txn: &Transaction<'_>,
        segment: &NetworkSegment,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(txn
            .query(
                "SELECT * FROM machine_interfaces mi WHERE mi.segment_id = $1",
                &[&segment.id()],
            )
            .await?
            .into_iter()
            .map(MachineInterface::from)
            .collect())
    }

    pub async fn find_by_machine_ids(
        txn: &Transaction<'_>,
        ids: Vec<&uuid::Uuid>,
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<MachineInterface>>> {
        let interfaces_result = txn
            .query(
                "SELECT * FROM machine_interfaces mi WHERE mi.machine_id=ANY($1)",
                &[&ids],
            )
            .await;

        interfaces_result
            .map(|rows| {
                rows.into_iter()
                    .map(MachineInterface::from)
                    .into_group_map_by(|interface| interface.machine_id)
            })
            .map_err(CarbideError::from)
    }

    pub fn address_ipv4(&self) -> Option<&Ipv4Addr> {
        self.address_ipv4.as_ref()
    }

    pub fn address_ipv6(&self) -> Option<&Ipv6Addr> {
        self.address_ipv6.as_ref()
    }

    pub async fn create(
        txn: &Transaction<'_>,
        machine: &Machine,
        segment: &NetworkSegment,
        macaddr: &MacAddress,
        address_v4: &AddressSelectionStrategy<Ipv4Addr>,
        address_v6: &AddressSelectionStrategy<Ipv6Addr>,
    ) -> CarbideResult<Self> {
        // If either requested addresses are auto-generated, we lock the entire table.
        if matches!(address_v4, AddressSelectionStrategy::Automatic(_))
            || matches!(address_v6, AddressSelectionStrategy::Automatic(_))
        {
            txn.query(
                "LOCK TABLE machine_interfaces IN ACCESS EXCLUSIVE MODE",
                &[],
            )
            .await?;
        };

        let interfaces = Self::find_by_network_segment(&txn, segment).await?;

        let new_ipv4 = match address_v4 {
            AddressSelectionStrategy::Empty => None,
            AddressSelectionStrategy::Static(ip) => Some(*ip),
            AddressSelectionStrategy::Automatic(ignore_absent) => {
                match segment.next_ipv4(
                    interfaces
                        .iter()
                        .filter(|interface| interface.address_ipv4().is_some())
                        .map(|interface| interface.address_ipv4().unwrap()),
                ) {
                    Err(CarbideError::NetworkSegmentMissingAddressFamilyError(_))
                        if *ignore_absent =>
                    {
                        None
                    }
                    Err(x) => return Err(x),
                    Ok(addr) => Some(addr),
                }
            }
        }
        .map(IpAddr::from); // IpAddr implements ToSql but the variants don't

        let new_ipv6 = match address_v6 {
            AddressSelectionStrategy::Empty => None,
            AddressSelectionStrategy::Static(ip) => Some(*ip),
            AddressSelectionStrategy::Automatic(ignore_absent) => {
                match segment.next_ipv6(
                    interfaces
                        .iter()
                        .filter(|interface| interface.address_ipv6().is_some())
                        .map(|interface| interface.address_ipv6().unwrap()),
                ) {
                    Err(CarbideError::NetworkSegmentMissingAddressFamilyError(_))
                        if *ignore_absent =>
                    {
                        None
                    }
                    Err(x) => return Err(x),
                    Ok(addr) => Some(addr),
                }
            }
        }
        .map(IpAddr::from); // IpAddr implements ToSql but the variants don't

        txn
            .query_one("INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, address_ipv4, address_ipv6) VALUES ($1::uuid, $2::uuid, $3::macaddr, $4::inet, $5::inet) RETURNING *", &[&machine.id(), &segment.id(), &macaddr, &new_ipv4, &new_ipv6])
            .await
            .map(MachineInterface::from)
            .map_err(|err| {
                // This is ugly
                match err.as_db_error() {
                    Some(db_error) if db_error.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION && db_error.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => CarbideError::NetworkSegmentDuplicateMacAddress(*macaddr),
                    _ => err.into()
                }
            })
    }
}
