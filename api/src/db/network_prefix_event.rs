use std::collections::HashMap;

use chrono::prelude::*;
use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};

use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::CarbideResult;
use crate::db::vpc_resource_action::VpcResourceAction;

#[derive(Debug, FromRow)]
pub struct NetworkPrefixEvent {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the vpc_resource_leaf that the event Applies ro
    network_prefix_id: uuid::Uuid,

    /// The action that was performed
    pub action: VpcResourceAction,

    /// The timestamp of the event
    timestamp: DateTime<Utc>,
}

/// Conversion from a NetworkPrefixEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<NetworkPrefixEvent> for rpc::NetworkPrefixEvent {
    fn from(event: NetworkPrefixEvent) -> rpc::NetworkPrefixEvent {
        let mut proto_event = rpc::NetworkPrefixEvent {
            id: event.id,
            network_prefix_id: Some(event.network_prefix_id.into()),
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

impl From<&NetworkPrefixEvent> for rpc::NetworkPrefixEvent {
    fn from(event: &NetworkPrefixEvent) -> Self {
        let mut proto_event = rpc::NetworkPrefixEvent {
            id: event.id,
            network_prefix_id: Some(event.network_prefix_id.into()),
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

impl NetworkPrefixEvent {
    /// Find a list of NetworkSegmenEvents given a list of network_segment Uuids.
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the network_segment Uuid and values of
    /// all the events.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_network_prefix_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM network_prefix_events WHERE network_prefix_id=ANY($1)",
        )
            .bind(ids)
            .fetch_all(&mut *txn)
            .await?
            .into_iter()
            .into_group_map_by(|event| event.network_prefix_id))
    }

    pub async fn for_network_prefix(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM network_prefix_events WHERE network_prefix_id=$1::uuid;",
        )
            .bind(id)
            .fetch_all(&mut *txn)
            .await?)
    }
}
