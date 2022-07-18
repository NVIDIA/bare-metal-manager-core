use super::{AddressSelectionStrategy, NetworkSegment, UuidKeyedObjectFilter};
use crate::db::Machine;
use crate::{
    db::network_segment::IpAllocationError, db::MachineInterfaceAddress, CarbideError,
    CarbideResult,
};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::{debug, warn};
use mac_address::MacAddress;
use rpc::forge::v0 as rpc;
use sqlx::{postgres::PgRow, Acquire, FromRow, Postgres, Row, Transaction};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

#[derive(Debug)]
pub struct MachineInterface {
    id: uuid::Uuid,
    domain_id: Option<uuid::Uuid>,
    pub machine_id: Option<uuid::Uuid>,
    segment_id: uuid::Uuid,
    mac_address: MacAddress,
    hostname: String,
    primary_interface: bool,
    addresses: Vec<MachineInterfaceAddress>,
}

impl<'r> FromRow<'r, PgRow> for MachineInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineInterface {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
            addresses: Vec::new(),
        })
    }
}

impl From<MachineInterface> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterface) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            machine_id: machine_interface.machine_id.map(|v| v.into()),
            segment_id: Some(machine_interface.segment_id.into()),
            hostname: machine_interface.hostname.into(),
            domain_id: machine_interface.domain_id.map(|d| d.into()),
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface.into(),
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.address.to_string())
                .collect(),
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

    pub async fn associate_interface_with_machine(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        Ok(sqlx::query_as(
            "UPDATE machine_interfaces SET machine_id=$1::uuid where id=$2::uuid RETURNING *",
        )
        .bind(machine_id)
        .bind(self.id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
            {
                CarbideError::OnePrimaryInterface
            }
            _ => CarbideError::from(err),
        })?)
    }

    /// Returns the UUID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn addresses(&self) -> &Vec<MachineInterfaceAddress> {
        &self.addresses
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

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<MachineInterface>>> {
        Ok(
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::List(machine_ids), "machine_id")
                .await?
                .into_iter()
                .into_group_map_by(|interface| interface.machine_id.unwrap()),
        )
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: uuid::Uuid,
    ) -> CarbideResult<MachineInterface> {
        let mut interfaces =
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::One(interface_id), "id").await?;
        match interfaces.len() {
            0 => Err(CarbideError::FindOneReturnedNoResultsError(interface_id)),
            1 => Ok(interfaces.remove(0)),
            _ => Err(CarbideError::FindOneReturnedManyResultsError(interface_id)),
        }
    }

    /// Do basic validating on existing macs and create the interface if it does not exist
    pub async fn validate_existing_mac_and_create(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        let mut existing_mac = MachineInterface::find_by_mac_address(txn, mac_address).await?;
        match &existing_mac.len() {
            0 => {
                debug!(
                    "No existing mac address[{0}] exists yet, creating one.",
                    mac_address
                );
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(segment) => {
                        // actually create the interface
                        let v = MachineInterface::create(
                            txn,
                            &segment,
                            &mac_address,
                            segment.subdomain_id,
                            Machine::generate_hostname_from_uuid(&uuid::Uuid::new_v4()),
                            true,
                            AddressSelectionStrategy::Automatic,
                        )
                        .await?;
                        Ok(v)
                    }
                }
            }
            1 => {
                debug!("An existing mac address[{0}] exists yet, validating the relay and returning it.", mac_address);
                let mac = existing_mac.remove(0);
                // Ensure the relay segment exists before blindly giving the mac address back out
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(_) => Ok(mac),
                }
            }
            _ => {
                warn!(
                    "More than existing mac address ({0}) for network segment (relay ip: {1})",
                    &mac_address, &relay
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
            }
        }
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        macaddr: &MacAddress,
        domain_id: Option<uuid::Uuid>,
        hostname: String,
        primary_interface: bool,
        addresses: AddressSelectionStrategy<'_>,
    ) -> CarbideResult<Self> {
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn.begin().await?;

        // If either requested addresses are auto-generated, we lock the entire table.
        let allocated_addresses = match addresses {
            AddressSelectionStrategy::Automatic => {
                sqlx::query("LOCK TABLE machine_interfaces IN ACCESS EXCLUSIVE MODE")
                    .execute(&mut inner_txn)
                    .await?;

                //
                // Get the next address for each prefix on this network segment.  Split the result
                // list into successes and failures.
                //
                let (success, failures) = segment
                    .next_address(&mut inner_txn)
                    .await?
                    .into_iter()
                    .fold((vec![], vec![]), |(mut successes, mut failures), item| {
                        match item {
                            Ok(address) => successes.push(address),
                            Err(error) => failures.push(error),
                        };

                        (successes, failures)
                    });

                //
                // If there's any failures, join the errors together and return it wrapped in a new
                // error type.
                //
                if !failures.is_empty() {
                    return Err(CarbideError::NetworkSegmentsExhausted(
                        failures
                            .into_iter()
                            .map(|failure| match failure {
                                IpAllocationError::PrefixExhausted(prefix) => format!(
                                    "Prefix: {0} ({1}) has exhausted all address space",
                                    prefix.id, prefix.prefix
                                ),
                            })
                            .join(", "),
                    ));
                } else {
                    //
                    // Otherwise just return the list of allocated IPs
                    //
                    success.into_iter().map(IpNetwork::from).collect_vec()
                }
            }
            _ => vec![],
        };

        let interface_id: (Uuid,) = sqlx::query_as("INSERT INTO machine_interfaces (segment_id, mac_address, hostname, domain_id, primary_interface) VALUES ($1::uuid, $2::macaddr, $3::varchar, $4::uuid, $5::bool) RETURNING id")
            .bind(segment.id())
            .bind(macaddr)
            .bind(hostname)
            .bind(domain_id)
            .bind(primary_interface)
            .fetch_one(&mut *inner_txn).await
            .map_err(|err: sqlx::Error| {
                match err {
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => CarbideError::NetworkSegmentDuplicateMacAddress(*macaddr),
                    sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) => CarbideError::OnePrimaryInterface,
                    _ => CarbideError::from(err)
                }
            })?;

        for address in allocated_addresses {
            sqlx::query("INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1::uuid, $2::inet)")
                .bind(&interface_id.0)
                .bind(address)
                .fetch_all(&mut *inner_txn).await?;
        }

        inner_txn.commit().await?;

        Ok(
            MachineInterface::find_by(txn, UuidKeyedObjectFilter::One(interface_id.0), "id")
                .await?
                .remove(0),
        )
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

    #[allow(clippy::needless_lifetimes)]
    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
        column: &'a str,
    ) -> CarbideResult<Vec<MachineInterface>> {
        let base_query = "SELECT * FROM machine_interfaces mi {where}".to_owned();

        let mut interfaces = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, MachineInterface>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, MachineInterface>(
                    &base_query
                        .replace("{where}", "WHERE mi.{column}=$1")
                        .replace("{column}", column),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, MachineInterface>(
                    &base_query
                        .replace("{where}", "WHERE mi.{column}=ANY($1)")
                        .replace("{column}", column),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        };

        let mut addresses_for_interfaces = MachineInterfaceAddress::find_for_interface(
            &mut *txn,
            UuidKeyedObjectFilter::List(
                interfaces
                    .iter()
                    .map(|interface| interface.id)
                    .collect::<Vec<Uuid>>()
                    .as_slice(),
            ),
        )
        .await?;

        interfaces.iter_mut().for_each(|interface| {
            if let Some(addresses) = addresses_for_interfaces.remove(&interface.id) {
                interface.addresses = addresses;
            } else {
                warn!("Interface {0} has no addresses", &interface.id);
            }
        });

        Ok(interfaces)
    }
}
