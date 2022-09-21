//!
//! Machine - represents a database-backed Machine object
//!
use std::convert::From;
use std::net::IpAddr;

use chrono::prelude::*;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use rust_fsm::StateMachine;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use ::rpc::MachineStateMachine;
use ::rpc::MachineStateMachineInput;
use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::db::machine_action::MachineAction;
use crate::db::machine_event::MachineEvent;
use crate::db::machine_interface::MachineInterface;
use crate::db::machine_state::MachineState;
use crate::human_hash;
use crate::{CarbideError, CarbideResult};

use super::UuidKeyedObjectFilter;

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

    vpc_leaf_id: Option<uuid::Uuid>,

    /// When this machine record was created
    created: DateTime<Utc>,

    /// When the machine record was last modified
    updated: DateTime<Utc>,

    /// When the machine was last deployed
    deployed: Option<DateTime<Utc>>,

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

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for Machine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Machine {
            id: row.try_get("id")?,
            vpc_leaf_id: row.try_get("vpc_leaf_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deployed: row.try_get("deployed")?,
            state: MachineState::Unknown,
            events: Vec::new(),
            interfaces: Vec::new(),
        })
    }
}

///
/// Implements conversion from a database-backed `Machine` to a Protobuf representation of the
/// Machine.
///
impl From<Machine> for rpc::Machine {
    fn from(machine: Machine) -> Self {
        rpc::Machine {
            id: Some(machine.id.into()),
            vpc_leaf_id: machine.vpc_leaf_id.map(|v| v.into()),
            created: Some(Timestamp {
                seconds: machine.created.timestamp(),
                nanos: 0,
            }),
            updated: Some(Timestamp {
                seconds: machine.updated.timestamp(),
                nanos: 0,
            }),
            deployed: machine.deployed.map(|ts| Timestamp {
                seconds: ts.timestamp(),
                nanos: 0,
            }),
            state: machine.state.to_string(),
            supported_instance_type: None,
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

impl Machine {
    pub async fn exists(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<bool> {
        let machine = Machine::find_one(&mut *txn, machine_id).await?;
        match machine {
            None => Ok(false),
            Some(_) => Ok(true),
        }
    }

    /// Create a machine object in the database
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        mut interface: MachineInterface,
    ) -> CarbideResult<Self> {
        match interface.machine_id {
            None => {
                let row: (Uuid,) =
                    sqlx::query_as("INSERT INTO machines DEFAULT VALUES RETURNING id")
                        .fetch_one(&mut *txn)
                        .await?;

                let machine = match Machine::find_one(&mut *txn, row.0).await {
                    Ok(Some(x)) => Ok(x),
                    Ok(None) => Err(CarbideError::DatabaseInconsistencyOnMachineCreate(row.0)),
                    Err(x) => Err(x),
                }?;

                interface
                    .associate_interface_with_machine(txn, &machine.id)
                    .await?;

                // Add the initial state
                machine
                    .advance(txn, &MachineStateMachineInput::Discover)
                    .await?;

                Ok(machine)
            }
            Some(x) => {
                log::info!("Machine already exists, returning machine {}", x);
                Ok(Machine::find_one(&mut *txn, x).await?.unwrap())
            }
        }
    }

    pub async fn associate_vpc_leaf_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
        vpc_leaf_id: uuid::Uuid,
    ) -> CarbideResult<Machine> {
        Ok(
            sqlx::query_as(
                "UPDATE machines SET vpc_leaf_id=$1::uuid where id=$2::uuid RETURNING *",
            )
            .bind(vpc_leaf_id)
            .bind(machine_id)
            .fetch_one(&mut *txn)
            .await?,
        )
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        uuid: uuid::Uuid,
    ) -> CarbideResult<Option<Self>> {
        Ok(Machine::find(txn, UuidKeyedObjectFilter::One(uuid))
            .await?
            .pop())
    }

    pub fn generate_hostname_from_uuid(uuid: &uuid::Uuid) -> String {
        human_hash::humanize(uuid, 2)
    }

    pub async fn find_existing_machines(
        txn: &mut Transaction<'_, Postgres>,
        macaddr: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Vec<(Uuid,)>> {
        let sql = r#"
        SELECT m.id FROM
            machines m
            INNER JOIN machine_interfaces mi
                ON m.id = mi.machine_id
            INNER JOIN network_segments ns
                ON mi.segment_id = ns.id
            INNER JOIN network_prefixes np
                ON np.segment_id = ns.id
            WHERE
                mi.mac_address = $1::macaddr
                AND
                $2::inet <<= np.prefix;
        "#;

        Ok(sqlx::query_as(sql)
            .bind(macaddr)
            .bind(IpNetwork::from(relay))
            .fetch_all(&mut *txn)
            .await?)
    }

    /// Returns the UUID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Returns the std::time::SystemTime for when the machine was initially discovered
    pub fn created(&self) -> chrono::DateTime<Utc> {
        self.created
    }

    /// Returns the std::time::SystemTime for when the machine was last updated
    pub fn updated(&self) -> chrono::DateTime<Utc> {
        self.updated
    }

    /// Returns the list of Events the machine has experienced
    pub fn events(&self) -> &Vec<MachineEvent> {
        &self.events
    }

    /// Returns the list of Interfaces this machine owns
    pub fn interfaces(&self) -> &Vec<MachineInterface> {
        &self.interfaces
    }

    pub fn vpc_leaf_id(&self) -> &Option<uuid::Uuid> {
        &self.vpc_leaf_id
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
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<MachineState> {
        let events = MachineEvent::for_machine(txn, &self.id).await?;
        let state_machine = self.state_machine(&events)?;
        Ok(MachineState::from(state_machine.state()))
    }

    fn state_machine(
        &self,
        events: &[MachineEvent],
    ) -> CarbideResult<StateMachine<MachineStateMachine>> {
        let mut machine: StateMachine<MachineStateMachine> = StateMachine::new();
        events
            .iter()
            .map(|event| machine.consume(&MachineStateMachineInput::from(&event.action)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CarbideError::InvalidState)?;

        Ok(machine)
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
        txn: &mut Transaction<'_, Postgres>,
        action: &MachineStateMachineInput,
    ) -> CarbideResult<bool> {
        // first validate the state change by getting the current state in the db
        let events = MachineEvent::for_machine(txn, &self.id).await?;
        let mut state_machine = self.state_machine(&events)?;
        state_machine
            .consume(action)
            .map_err(CarbideError::InvalidState)?;

        let id: (i64,) = sqlx::query_as(
            "INSERT INTO machine_events (machine_id, action) VALUES ($1::uuid, $2) RETURNING id",
        )
        .bind(self.id())
        .bind(MachineAction::from(action))
        .fetch_one(txn)
        .await?;

        log::info!("Event ID is {}", id.0);

        Ok(true)
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
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<Machine>> {
        let base_query = "SELECT * FROM machines m {where} GROUP BY m.id".to_owned();

        let mut all_machines: Vec<Machine> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=$1"))
                    .bind(uuid)
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=ANY($1)"))
                    .bind(list)
                    .fetch_all(&mut *txn)
                    .await?
            }
        };

        let all_uuids = all_machines.iter().map(|m| m.id).collect::<Vec<Uuid>>();

        let mut events_for_machine =
            MachineEvent::find_by_machine_ids(&mut *txn, &all_uuids).await?;

        let mut interfaces_for_machine =
            MachineInterface::find_by_machine_ids(&mut *txn, &all_uuids).await?;

        all_machines.iter_mut().for_each(|machine| {
            if let Some(events) = events_for_machine.remove(&machine.id) {
                machine.events = events;
            } else {
                log::warn!("Machine {0} () has no events", machine.id);
            }

            if let Some(interfaces) = interfaces_for_machine.remove(&machine.id) {
                machine.interfaces = interfaces;
            } else {
                log::warn!("Machine {0} () has no interfaces", machine.id);
            }

            machine.state = machine
                .state_machine(&machine.events)
                .map_or(MachineState::Unknown, |m| MachineState::from(m.state()));
        });

        Ok(all_machines)
    }
}

#[cfg(test)]
mod test {}
