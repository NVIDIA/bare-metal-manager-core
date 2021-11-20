use super::{AddressSelectionStrategy, Machine, NetworkSegment};
use crate::{CarbideError, CarbideResult};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::error;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

impl<'r> sqlx::FromRow<'r, PgRow> for MachineInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let possible_address_ipv4: Option<IpNetwork> = row.try_get("address_ipv4")?;
        let possible_address_ipv6: Option<IpNetwork> = row.try_get("address_ipv6")?;

        let address_ipv4 = match possible_address_ipv4 {
            Some(IpNetwork::V4(network)) if network.prefix() == 32 => Ok(Some(network.ip())),
            Some(IpNetwork::V4(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in address_ipv4 ({}) is not a single host",
                network
            ))),
            Some(IpNetwork::V6(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in address_ipv4 ({}) is not an IPv4 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        let address_ipv6 = match possible_address_ipv6 {
            Some(IpNetwork::V6(network)) if network.prefix() == 128 => Ok(Some(network.ip())),
            Some(IpNetwork::V6(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in address_ipv4 ({}) is not a single host",
                network
            ))),
            Some(IpNetwork::V4(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in address_ipv4 ({}) is not an IPv6 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        Ok(MachineInterface {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            mac_address: row.try_get("mac_address")?,
            address_ipv4,
            address_ipv6,
        })
    }
}

impl From<MachineInterface> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterface) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            machine_id: Some(machine_interface.machine_id.into()),
            segment_id: Some(machine_interface.segment_id.into()),

            mac_address: machine_interface.mac_address.to_string(),
            address_ipv4: machine_interface.address_ipv4.map(|a| a.to_string()),
            address_ipv6: machine_interface.address_ipv6.map(|a| a.to_string()),
        }
    }
}

impl MachineInterface {
    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        macaddr: MacAddress,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(
            sqlx::query_as(
                "SELECT * FROM machine_interfaces mi WHERE mi.mac_address = $1::macaddr",
            )
            .bind(macaddr)
            .fetch_all(txn)
            .await?,
        )
    }

    pub async fn find_by_network_segment(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(
            sqlx::query_as("SELECT * FROM machine_interfaces mi WHERE mi.segment_id = $1")
                .bind(segment.id())
                .fetch_all(txn)
                .await?,
        )
    }

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: Vec<uuid::Uuid>,
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<MachineInterface>>> {
        let interfaces: Vec<MachineInterface> =
            sqlx::query_as("SELECT * FROM machine_interfaces mi WHERE mi.machine_id=ANY($1)")
                .bind(ids)
                .fetch_all(&mut *txn)
                .await?;

        Ok(interfaces
            .into_iter()
            .into_group_map_by(|interface| interface.machine_id))
    }

    pub fn address_ipv4(&self) -> Option<&Ipv4Addr> {
        self.address_ipv4.as_ref()
    }

    pub fn address_ipv6(&self) -> Option<&Ipv6Addr> {
        self.address_ipv6.as_ref()
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
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
            sqlx::query("LOCK TABLE machine_interfaces IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *txn)
                .await?;
        };

        let interfaces = Self::find_by_network_segment(&mut *txn, segment).await?;

        let new_ipv4 = match address_v4 {
            AddressSelectionStrategy::Empty => None,
            AddressSelectionStrategy::Static(ip) => Some(*ip),
            AddressSelectionStrategy::Automatic(ignore_absent) => {
                match segment.next_ipv4(
                    interfaces
                        .iter()
                        .filter_map(|interface| interface.address_ipv4()),
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
                        .filter_map(|interface| interface.address_ipv6()),
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

        Ok(sqlx::query_as("INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, address_ipv4, address_ipv6) VALUES ($1::uuid, $2::uuid, $3::macaddr, $4::inet, $5::inet) RETURNING *")
            .bind(machine.id())
            .bind(segment.id)
            .bind(macaddr)
            .bind(new_ipv4.map(IpNetwork::from ))
            .bind(new_ipv6.map(IpNetwork::from ))
            .fetch_one(&mut *txn).await
            .map_err(|err| {
                error!("TODO: convert to proper errror {:#?}", err);
                err
            })?)
    }
}
