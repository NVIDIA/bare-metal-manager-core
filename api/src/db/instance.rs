use std::convert::{TryFrom, TryInto};

use chrono::prelude::*;
use sqlx::{FromRow, Postgres};

use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::{CarbideError, CarbideResult};

#[derive(Debug, FromRow)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
}

pub struct NewInstance {
    pub machine_id: uuid::Uuid,
}

impl NewInstance {
    pub fn new(machine_id: uuid::Uuid) -> Self {
        Self { machine_id }
    }
}

impl From<Instance> for rpc::Instance {
    fn from(src: Instance) -> Self {
        rpc::Instance {
            id: Some(src.id.into()),
            segment_id: None,
            machine_id: Some(src.machine_id.into()),
            user_data: None,
            custom_ipxe: None,
            ssh_keys: vec![],
            requested: Some(Timestamp {
                seconds: src.requested.timestamp(),
                nanos: 0,
            }),
            started: Some(Timestamp {
                seconds: src.started.timestamp(),
                nanos: 0,
            }),
            finished: src.finished.map(|t| Timestamp {
                seconds: t.timestamp(),
                nanos: 0,
            }),
        }
    }
}

impl TryFrom<rpc::Instance> for NewInstance {
    type Error = CarbideError;

    fn try_from(value: rpc::Instance) -> Result<Self, Self::Error> {
        if value.id.is_some() {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Instance",
            )));
        }
        Ok(NewInstance {
            machine_id: value
                .machine_id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
        })
    }
}

impl Instance {
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }
}

impl NewInstance {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Instance> {
        Ok(
            sqlx::query_as("INSERT INTO instances (machine_id) VALUES ($1::uuid) RETURNING *")
                .bind(&self.machine_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}
