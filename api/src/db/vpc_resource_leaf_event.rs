//use super::MachineAction;
use crate::CarbideResult;
use chrono::prelude::*;
use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};
use std::collections::HashMap;

use crate::db::vpc_resource_action::VpcResourceAction;

#[derive(Debug, FromRow)]
pub struct VpcResourceLeafEvent {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the vpc_resource_leaf that the event Applies ro
    vpc_leaf_id: uuid::Uuid,

    /// The action that was performed
    pub action: VpcResourceAction,

    /// The timestamp of the event
    timestamp: DateTime<Utc>,
}

/*
/// Conversion from a VpcResourceEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<VpcResourceLeafEvent> for rpc::VpcResourceLeafEvent {
    fn from(event: VpcResourceLeafEvent) -> rpc::VpcResourceLeafEvent {
        let mut proto_event = rpc::VpcResourceLeafEvent {
            id: event.id,
            vpc_leaf_id: Some(event.vpc_leaf_id.into()),
            time: Some(Timestamp {
                seconds: event.timestamp.timestamp(),
                nanos: 0,
            }),
            event: 0,
        };

        proto_event.set_event(event.action.into());

        proto_event
    }
}
*/

impl VpcResourceLeafEvent {
    pub fn id(&self) -> &i64 {
        &self.id
    }

    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }

    pub fn vpc_leaf_id(&self) -> &uuid::Uuid {
        &self.vpc_leaf_id
    }

    pub fn action(&self) -> &VpcResourceAction {
        &self.action
    }

    /// Find a list of VpcResourceEvents given a list of vpc_resource Uuids.
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the vpc_resource Uuid and values of
    /// all the events.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_vpc_leaf_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM vpc_resource_leaf_events WHERE vpc_leaf_id=ANY($1)",
        )
        .bind(ids)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .into_group_map_by(|event| event.vpc_leaf_id))
    }

    pub async fn for_leaf(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM vpc_resource_leaf_events WHERE vpc_leaf_id=$1::uuid;",
        )
        .bind(id)
        .fetch_all(&mut *txn)
        .await?)
    }
}
