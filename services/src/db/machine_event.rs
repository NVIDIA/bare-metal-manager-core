use super::MachineAction;
use crate::{CarbideError, CarbideResult};
use itertools::Itertools;
use log::info;
use std::collections::HashMap;

use rpc::v0 as rpc;

/// Representation of an event (state transition) on a machine.
///
/// The database stores a list of the events (and not state changes).  The state machine in the
/// database schema converts the state machine edges into a `current state` representation.  For
/// instance, creating an event called `adopt` on a Machine where the last event is `discover` will
/// result in a MachineState of `adopted`
///
#[derive(Debug)]
pub struct MachineEvent {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the machine that the event Applies to (due to Rust self-referential rules
    /// around circular references, this is a UUID, not a machine type).
    machine_id: uuid::Uuid,

    /// The action that was performed
    action: MachineAction,

    /// The version of the state machine that generated this event
    version: i32,

    /// The timestamp of the event
    timestamp: std::time::SystemTime,
}

/// Conversion from a tokio_postgres::Row into a MachineEvent
///
/// Panics if the schema is changed in a backward incompatible way
///
impl From<tokio_postgres::Row> for MachineEvent {
    fn from(row: tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            action: row.get("action"),
            version: row.get("version"),
            timestamp: row.get("timestamp"),
        }
    }
}

/// Conversion from a MachineEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<MachineEvent> for rpc::MachineEvent {
    fn from(event: MachineEvent) -> rpc::MachineEvent {
        let mut proto_event = rpc::MachineEvent {
            id: event.id.into(),
            machine_id: Some(event.machine_id.into()),
            time: Some(event.timestamp.into()),
            version: event.version,
            event: 0, // 0 is usually null in protobuf I guess
        };

        proto_event.set_event(event.action.into());

        info!("proto {:?}", &proto_event);

        proto_event
    }
}

impl MachineEvent {
    /// Find a list of MachineEvents given a list of machine Uuids.
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the machine Uuid and values of
    /// all the events.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_by_machine_ids(
        txn: &tokio_postgres::Transaction<'_>,
        ids: Vec<&uuid::Uuid>,
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        let events = txn
            .query(
                "SELECT * FROM machine_events WHERE machine_id=ANY($1)",
                &[&ids],
            )
            .await;

        events
            .map(|rows| {
                rows.into_iter()
                    .map(MachineEvent::from)
                    .into_group_map_by(|event| event.machine_id)
                    .into_iter()
                    .collect::<HashMap<uuid::Uuid, Vec<MachineEvent>>>()
            })
            .map_err(CarbideError::from)
    }
}
