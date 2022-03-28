use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use rpc::v0 as rpc;

use crate::{CarbideError, CarbideResult, Domain};

use super::{AbsentSubnetStrategy, AddressSelectionStrategy, Machine, NetworkSegment};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "prevent_duplicate_mac_for_network";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

#[derive(Debug)]
pub struct MachineInterface {
    id: uuid::Uuid,

    domain_id: Option<uuid::Uuid>,
    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,
    hostname: String,

    mac_address: MacAddress,
    primary_interface: bool,

    address_ipv4: Option<Ipv4Addr>,
    address_ipv6: Option<Ipv6Addr>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for MachineInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let address_ipv4 = if let Some(address_ipv4) = row.try_get("address_ipv4")? {
            Some(
                crate::network_to_host_ipv4(address_ipv4)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))?,
            )
        } else {
            None
        };

        let address_ipv6 = if let Some(address_ipv6) = row.try_get("address_ipv6")? {
            Some(
                crate::network_to_host_ipv6(address_ipv6)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))?,
            )
        } else {
            None
        };

        Ok(MachineInterface {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
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
            hostname: machine_interface.hostname.into(),
            domain_id: machine_interface.domain_id.map(|d| d.into()),

            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface.into(),
            address_ipv4: machine_interface.address_ipv4.map(|a| a.to_string()),
            address_ipv6: machine_interface.address_ipv6.map(|a| a.to_string()),
        }
    }
}

impl MachineInterface {
    /// Update machine interface hostname
    ///
    /// This updates the machine_interfaces hostname which will render the old name in-accessible after the DNS
    /// TTL expires on recursive resolvers.  The authoritative resolver is updated immediately.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `new_hostname` - The new hostname, which is subject to DNS validation rules (todo!())
    pub async fn update_hostname(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        new_hostname: &str,
    ) -> CarbideResult<&MachineInterface> {
        let (hostname,) =
            sqlx::query_as("UPDATE machine_interfaces SET hostname=$1 RETURNING hostname")
                .bind(new_hostname)
                .fetch_one(txn)
                .await?;

        self.hostname = hostname;

        Ok(self)
    }

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
        ids: &[uuid::Uuid],
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
        domain_id: Option<uuid::Uuid>,
        hostname: String,
        primary_interface: bool,
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
                        if *ignore_absent == AbsentSubnetStrategy::Ignore =>
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
                        if *ignore_absent == AbsentSubnetStrategy::Ignore =>
                    {
                        None
                    }
                    Err(x) => return Err(x),
                    Ok(addr) => Some(addr),
                }
            }
        }
        .map(IpAddr::from); // IpAddr implements ToSql but the variants don't

        Ok(sqlx::query_as("INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, hostname, domain_id, primary_interface, address_ipv4, address_ipv6) VALUES ($1::uuid, $2::uuid, $3::macaddr, $4::varchar, $5::uuid, $6::bool, $7::inet, $8::inet) RETURNING *")
            .bind(machine.id())
            .bind(segment.id)
            .bind(macaddr)
            .bind(hostname)
            .bind(domain_id)
            .bind(primary_interface)
            .bind(new_ipv4.map(IpNetwork::from))
            .bind(new_ipv6.map(IpNetwork::from))
            .fetch_one(&mut *txn).await
            .map_err(|err: sqlx::Error| {
                match err {
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => CarbideError::NetworkSegmentDuplicateMacAddress(*macaddr),
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) => CarbideError::OnePrimaryInterface,
                    _ => CarbideError::from(err)
                }
            })?)
    }

    /// Get a reference to the machine interface's segment id.
    pub fn segment_id(&self) -> Uuid {
        self.segment_id
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn primary_interface(&self) -> bool {
        self.primary_interface
    }
}
