use super::{AddressSelectionStrategy, Machine, NetworkSegment, UuidKeyedObjectFilter};
use crate::{
    db::network_segment::IpAllocationError, db::MachineInterfaceAddress, CarbideError,
    CarbideResult,
};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::warn;
use mac_address::MacAddress;
use rpc::v0 as rpc;
use sqlx::{postgres::PgRow, Acquire, FromRow, Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

#[derive(Debug)]
pub struct MachineInterface {
    id: uuid::Uuid,
    domain_id: Option<uuid::Uuid>,
    machine_id: uuid::Uuid,
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
            machine_id: Some(machine_interface.machine_id.into()),
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
                .into_group_map_by(|interface| interface.machine_id),
        )
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine: &Machine,
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

        let interface_id: (Uuid,) = sqlx::query_as("INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, hostname, domain_id, primary_interface) VALUES ($1::uuid, $2::uuid, $3::macaddr, $4::varchar, $5::uuid, $6::bool) RETURNING id")
            .bind(machine.id())
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
