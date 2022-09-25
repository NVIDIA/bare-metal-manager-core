use std::collections::HashMap;

use chrono::prelude::*;
use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};

use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::db::vpc_resource_action::VpcResourceAction;
use crate::CarbideResult;

#[derive(Debug, FromRow, Clone)]
pub struct InstanceSubnetEvent {
    /// The numeric identifier of the event, this should not be exposed to consumers of this API,
    /// it is not secure.
    id: i64,

    /// The UUID of the instance_subnet that the event Applies to
    instance_subnet_id: uuid::Uuid,

    /// The action that was performed
    pub action: VpcResourceAction,

    /// The timestamp of the event
    timestamp: DateTime<Utc>,
}

/// Conversion from a InstanceSubnetEvent object into a Protocol buffer representation for transmission
/// over the wire.
impl From<InstanceSubnetEvent> for rpc::InstanceSubnetEvent {
    fn from(event: InstanceSubnetEvent) -> rpc::InstanceSubnetEvent {
        let mut proto_event = rpc::InstanceSubnetEvent {
            id: event.id,
            instance_subnet_id: Some(event.instance_subnet_id.into()),
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

impl From<&InstanceSubnetEvent> for rpc::InstanceSubnetEvent {
    fn from(event: &InstanceSubnetEvent) -> Self {
        let mut proto_event = rpc::InstanceSubnetEvent {
            id: event.id,
            instance_subnet_id: Some(event.instance_subnet_id.into()),
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

impl InstanceSubnetEvent {
    /// Find a list of InstanceSubnetEvents given a list of instance_subnet Uuids.
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the instance_subnet Uuid and values of
    /// all the events.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_instance_subnet_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: &[uuid::Uuid],
    ) -> CarbideResult<HashMap<uuid::Uuid, Vec<Self>>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM instance_subnet_events WHERE instance_subnet_id=ANY($1)",
        )
        .bind(ids)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .into_group_map_by(|event| event.instance_subnet_id))
    }

    pub async fn for_instance_subnet(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        Ok(sqlx::query_as::<_, Self>(
            "SELECT * FROM instance_subnet_events WHERE instance_subnet_id=$1::uuid;",
        )
        .bind(id)
        .fetch_all(&mut *txn)
        .await?)
    }
}
