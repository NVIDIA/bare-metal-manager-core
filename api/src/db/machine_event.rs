use super::MachineAction;
use crate::CarbideResult;
use itertools::Itertools;
use sqlx::{Postgres, Transaction};
use std::collections::HashMap;
use chrono::prelude::*;

use rpc::v0 as rpc;

/// Representation of an event (state transition) on a machine.
///
/// The database stores a list of the events (and not state changes).  The state machine in the
/// database schema converts the state machine edges into a `current state` representation.  For
/// instance, creating an event called `adopt` on a Machine where the last event is `discover` will
/// result in a MachineState of `adopted`
///
#[derive(Debug, sqlx::FromRow)]
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
    timestamp: DateTime<Utc>,
}

/// Conversion from a MachineEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<MachineEvent> for rpc::MachineEvent {
    fn from(event: MachineEvent) -> rpc::MachineEvent {
        let mut proto_event = rpc::MachineEvent {
            id: event.id,
            machine_id: Some(event.machine_id.into()),
            time: Some( rpc::Timestamp { seconds: event.timestamp.timestamp(), nanos: 0 }),
            version: event.version,
            event: 0, // 0 is usually null in protobuf I guess
        };

        proto_event.set_event(event.action.into());

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
        txn: &mut Transaction<'_, Postgres>,
        ids: Vec<uuid::Uuid>,
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        Ok(
            sqlx::query_as::<_, Self>("SELECT * FROM machine_events WHERE machine_id=ANY($1)")
                .bind(ids)
                .fetch_all(&mut *txn)
                .await?
                .into_iter()
                .into_group_map_by(|event| event.machine_id),
        )
    }
}
