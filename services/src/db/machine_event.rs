use super::MachineAction;
use crate::{CarbideError, CarbideResult};
use itertools::Itertools;
use std::collections::HashMap;
use log::info;

#[derive(Debug)]
pub struct MachineEvent {
    id: i64,
    machine_id: uuid::Uuid,
    action: MachineAction,
    version: i32,
    timestamp: std::time::SystemTime,
}

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

impl From<MachineEvent> for rpc::MachineEvent {
    fn from(event: MachineEvent) -> rpc::MachineEvent {
        let mut proto_event = rpc::MachineEvent {
            id: event.id.into(),
            machine_id: Some(event.machine_id.into()),
            time: Some(event.timestamp.into()),
            version: event.version,
            event: 0,
        };

        proto_event.set_event(event.action.into());

        info!("proto {:?}", &proto_event);
        proto_event
    }
}

impl MachineEvent {
    pub async fn find_by_machine_ids(
        txn: &tokio_postgres::Transaction<'_>,
        ids: Vec<&uuid::Uuid>,
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        let events = txn.query(
            "SELECT * FROM machine_events WHERE machine_id=ANY($1)",
            &[&ids],
        ).await;

        info!("events = {:?}", &events);

        events.map(|result| {
            result
                .into_iter()
                .map(MachineEvent::from)
                .into_group_map_by(|event| event.machine_id)
                .into_iter()
                .collect::<HashMap<uuid::Uuid, Vec<MachineEvent>>>()
        })
        .map_err(CarbideError::from)
    }
}
