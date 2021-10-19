//!
//! Machine - represents a database-backed Machine object
//!
use crate::{CarbideError, CarbideResult};
use log::{debug, info, warn};

use std::collections::HashMap;
use std::convert::From;
use std::str;

use eui48::MacAddress;

use tokio_postgres::Transaction;

use super::AddressSelectionStrategy;
use super::MachineAction;
use super::MachineEvent;
use super::MachineInterface;
use super::MachineState;
use super::NetworkSegment;

use std::net::IpAddr;

use rpc::v0 as rpc;

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct Machine {
    ///
    /// The UUID of the machine, this is an internal identifier in the database that's unique for
    /// all machines managed by this instance of carbide.
    ///
    id: uuid::Uuid,

    ///
    /// This is the FQDN of the machine that's used to access the machine remotely.  It's IP
    /// address is mapped to the IP address on the [MachineInterface][interface] that's `primary`.
    ///
    /// [interface]: crate::db::MachineInterface
    ///
    fqdn: String,

    /// When this machine record was created
    created: std::time::SystemTime,

    /// When the machine record was last modified
    modified: std::time::SystemTime,

    /// The current state of the machine
    state: MachineState,

    /// A list of [MachineEvent][event]s that this machine has experienced
    ///
    /// [event]: crate::db::MachineEvent
    events: Vec<MachineEvent>,

    /// A list of [MachineInterface][interface]s that this machine owns
    ///
    /// [event]: crate::db::MachineInterface
    interfaces: Vec<MachineInterface>,
}

///
/// A parameter to find() to filter machines by Uuid;
///
pub enum MachineIdsFilter<'a> {
    /// Don't filter by uuid
    All,

    /// Filter by a list of uuids
    List(Vec<&'a uuid::Uuid>),

    /// Retrieve a single machine
    One(&'a uuid::Uuid),
}

///
/// Implements conversion from a database-backed `Machine` to a Protobuf representation of the
/// Machine.
///
impl From<Machine> for rpc::Machine {
    fn from(machine: Machine) -> Self {
        rpc::Machine {
            id: Some(machine.id.into()),
            fqdn: machine.fqdn,
            created: Some(machine.created.into()),
            modified: Some(machine.modified.into()),
            state: Some(machine.state.into()),
            events: machine
                .events
                .into_iter()
                .map(|event| event.into())
                .collect(),
            interfaces: machine
                .interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
        }
    }
}

///
/// Implements conversion from a PostgreSQL row struct into a machine.
///
impl From<tokio_postgres::Row> for Machine {
    fn from(row: tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            fqdn: row.get("fqdn"),
            created: row.get("created"),
            modified: row.get("modified"),
            state: row.get("state"),
            events: Vec::new(),
            interfaces: Vec::new(),
        }
    }
}

impl Machine {
    /// Create a machine object in the database
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `fqdn` - initial hostname used to identify this host
    ///
    pub async fn create(
        txn: &tokio_postgres::Transaction<'_>,
        fqdn: String,
    ) -> CarbideResult<Self> {
        let created_machine_row = txn
            .query_one(
                "INSERT INTO machines (fqdn) VALUES ($1) RETURNING id",
                &[&fqdn],
            )
            .await?;

        let created_id = created_machine_row.get("id");
        match Machine::find_one(txn, created_id).await {
            Ok(Some(x)) => Ok(x),
            Ok(None) => Err(CarbideError::DatabaseInconsistencyOnMachineCreate(
                created_id,
            )),
            Err(x) => Err(x),
        }
    }

    pub async fn find_one(
        txn: &tokio_postgres::Transaction<'_>,
        uuid: uuid::Uuid,
    ) -> CarbideResult<Option<Self>> {
        Self::find(txn, MachineIdsFilter::One(&uuid))
            .await
            .map(|v| v.into_iter().next())
    }

    // TODO(ajf): doesn't belong here
    pub fn generate_hostname_from_uuid(mut id: u128) -> String {
        let alpha_lower = b'a'..=b'z';
        let numeric = b'0'..=b'9';

        let space = alpha_lower.chain(numeric).collect::<Vec<u8>>();

        assert_eq!(space.len(), 36);

        let mut output = Vec::with_capacity(std::mem::size_of::<u8>() * 22);
        while id > 0 {
            output.push(space[(id % 36) as usize]);
            id = id.checked_div(36).unwrap();
        }
        String::from(str::from_utf8(&output).unwrap())
    }

    /// Discovery of a machine
    ///
    /// A machine has DHCPed and we will attempt to find a machine in the database, or we create
    /// one with an autogenerated hostname using the default domain name found in the
    /// [NetworkSegment][crate::db::NetworkSegment] identified by the DHCP relay's network this
    /// DHCP DISCOVER request was found.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `macaddr` - The eui48::MacAddress of the booting machine
    /// * `relay` - The IP address of the DHCP relay servicing the request.
    pub async fn discover(
        txn: &mut tokio_postgres::Transaction<'_>,
        macaddr: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        // Find machines that have the mac address on the subnet being relayed
        // It's possible to have duplicate mac addresses on different subnets.
        let sql = r#"
        SELECT m.id FROM
            machines m
            INNER JOIN machine_interfaces mi
                ON m.id = mi.machine_id
            INNER JOIN network_segments ns
                ON mi.segment_id = ns.id
            WHERE
                mi.mac_address = $1::macaddr
                AND
                (($2::inet <<= ns.subnet_ipv4) OR ($2::inet <<= ns.subnet_ipv6));
        "#;

        let mut results = txn
            .query(sql, &[&macaddr, &relay])
            .await?
            .into_iter()
            .map(|row| row.get::<&str, uuid::Uuid>("id"))
            .collect::<Vec<uuid::Uuid>>();

        match &results.len() {
            0 => {
                info!("No existing machine with mac address {} using network with relay: {}, creating one.", macaddr, relay);

                match NetworkSegment::for_relay(txn, relay).await? {
                    Some(segment) => {
                        let generated_hostname =
                            Self::generate_hostname_from_uuid(uuid::Uuid::new_v4().as_u128());
                        let generated_fqdn =
                            format!("{}.{}", generated_hostname, segment.subdomain());

                        debug!("Generated hostname {}", generated_fqdn);

                        let machine_create_transaction = txn.transaction().await?;

                        let machine =
                            Machine::create(&machine_create_transaction, generated_fqdn).await?;

                        let _ = MachineInterface::create(
                            &machine_create_transaction,
                            &machine,
                            &segment,
                            &macaddr,
                            &AddressSelectionStrategy::Automatic(true),
                            &AddressSelectionStrategy::Automatic(true),
                        )
                        .await?;

                        machine_create_transaction.commit().await?;

                        Ok(Self::find(txn, MachineIdsFilter::List(vec![&machine.id]))
                            .await?
                            .remove(0))
                    }
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                }
            }
            1 => {
                let id = results.remove(0);
                Machine::find_one(txn, id).await.and_then(|machine| {
                    if let Some(machine) = machine {
                        Ok(machine)
                    } else {
                        Err(CarbideError::DatabaseInconsistencyOnMachineCreate(id))
                    }
                })
            }
            _ => {
                warn!(
                    "More than one mac address ({0}) for network segment (relay ip: {1})",
                    &macaddr, &relay
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(macaddr))
            }
        }
    }

    /// Returns the UUID of the machine object
    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    /// Returns the std::time::SystemTime for when the machine was initially discovered
    pub fn created(&self) -> std::time::SystemTime {
        self.created
    }

    /// Returns the std::time::SystemTime for when the machine was last updated
    pub fn modified(&self) -> std::time::SystemTime {
        self.modified
    }

    /// Returns a reference to the FQDN of the machine
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// Returns the list of Events the machine has experienced
    pub fn events(&self) -> &Vec<MachineEvent> {
        &self.events
    }

    /// Returns the list of Interfaces this machine owns
    pub fn interfaces(&self) -> &Vec<MachineInterface> {
        &self.interfaces
    }

    /// Update this machine's FQDN
    ///
    /// This updates the machines FQDN which will render the old name in-accessible after the DNS
    /// TTL expires on recursive resolvers.  The authoritative resolver is updated immediately.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `new_fqdn` - The new FQDN, which is subject to DNS validation rules (todo!())
    pub async fn update_fqdn(
        &mut self,
        txn: &Transaction<'_>,
        new_fqdn: &str,
    ) -> CarbideResult<&Machine> {
        let result = txn
            .query_one(
                "UPDATE machines SET fqdn=$1 RETURNING fqdn,modified",
                &[&new_fqdn],
            )
            .await?;

        self.fqdn = result.get("fqdn");
        self.modified = result.get("modified");

        Ok(self)
    }

    /// Return the current state of the machine based on the sequence of events the machine has
    /// experienced.
    ///
    /// This object does not store the current state, but calculates it from the actions that have
    /// been performed on the machines.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn current_state(
        &self,
        txn: &tokio_postgres::Transaction<'_>,
    ) -> CarbideResult<MachineState> {
        MachineState::for_machine(self, txn).await
    }

    /// Perform an arbitrary action to a Machine and advance it to the next state given the last
    /// state.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `action` - A reference to a MachineAction enum
    ///
    pub async fn advance(
        &self,
        dbc: &tokio_postgres::Transaction<'_>,
        action: &MachineAction,
    ) -> CarbideResult<bool> {
        let row = dbc
            .query_one(
                "INSERT INTO machine_events (machine_id, action) VALUES ($1, $2) RETURNING id",
                &[&self.id(), &action],
            )
            .await?;

        log::info!("Event ID is {}", row.get::<&str, uuid::Uuid>("id"));

        Ok(true)
    }

    /// Perform action `Fail` on the Machine advancing it to the next state given the last
    /// state
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn fail(&self, txn: &tokio_postgres::Transaction<'_>) -> CarbideResult<bool> {
        self.advance(txn, &MachineAction::Fail).await
    }

    /// Perform action `Commission` on the Machine advancing it to the next state given the last
    /// state
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn commission(&self, txn: &tokio_postgres::Transaction<'_>) -> CarbideResult<bool> {
        self.advance(txn, &MachineAction::Commission).await
    }

    /// Find machines given a set of criteria, right now just returns all machines because there's
    /// no way to filter the machines.
    ///
    /// TODO(ajf): write a query langauge???
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn find(
        txn: &tokio_postgres::Transaction<'_>,
        id_filter: MachineIdsFilter<'_>,
    ) -> CarbideResult<Vec<Machine>> {
        let base_query = "SELECT m.*,machine_state_machine(me.action,me.version) AS state FROM machines m JOIN machine_events me ON me.machine_id=m.id ";

        let query = match id_filter {
            MachineIdsFilter::All => {
                txn.query(&format!("{0} GROUP BY m.id", base_query)[..], &[])
                    .await
            }
            MachineIdsFilter::One(ref uuid) => {
                txn.query(
                    &format!("{0} WHERE m.id=$1 GROUP BY m.id", base_query)[..],
                    &[&uuid],
                )
                .await
            }
            MachineIdsFilter::List(ref list) => {
                txn.query(
                    &format!("{0} WHERE m.id=ANY($1) GROUP BY m.id", base_query)[..],
                    &[&list],
                )
                .await
            }
        }?;

        let mut machines = query
            .into_iter()
            .fold(HashMap::new(), |mut accumulator, row| {
                let machine = Machine::from(row);

                accumulator.insert(machine.id, machine);

                accumulator
            })
            .into_iter()
            .collect::<HashMap<uuid::Uuid, Machine>>();

        let events_future = MachineEvent::find_by_machine_ids(txn, machines.keys().collect());

        let interfaces_future =
            MachineInterface::find_by_machine_ids(txn, machines.keys().collect());

        let (events_for_machine_result, interfaces_for_machine_result) =
            futures::join!(events_future, interfaces_future);

        let mut events_for_machine = events_for_machine_result?;
        let mut interfaces_for_machine = interfaces_for_machine_result?;

        let hint_length = machines.len();

        let final_machine_list = machines.drain().fold(
            Vec::with_capacity(hint_length),
            move |mut accumulator, (uuid, mut machine)| {
                if let Some(events) = events_for_machine.remove(&uuid) {
                    machine.events = events;
                } else {
                    warn!("Machine {0} ({1}) has no events", machine.id, machine.fqdn);
                }

                if let Some(interfaces) = interfaces_for_machine.remove(&uuid) {
                    machine.interfaces = interfaces;
                } else {
                    warn!(
                        "Machine {0} ({1}) has no interfaces",
                        machine.id, machine.fqdn
                    );
                }
                accumulator.push(machine);
                accumulator
            },
        );

        Ok(final_machine_list)
    }
}

#[cfg(test)]
mod test {}
