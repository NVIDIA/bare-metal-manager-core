use std::convert::{TryFrom, TryInto};

use chrono::prelude::*;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};

use crate::{CarbideError, CarbideResult};
use rpc::v0 as rpc;

#[derive(Debug)]
pub struct Instance {
    pub id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    pub requested: DateTime<Utc>,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Instance {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Instance {
            id: row.try_get("id")?,
            machine_id: row.try_get("machine_id")?,
            requested: row.try_get("requested")?,
            started: row.try_get("started")?,
            finished: row.try_get("finished")?,
        })
    }
}

pub struct NewInstance {
    pub machine_id: uuid::Uuid,
}

impl From<Instance> for rpc::Instance {
    fn from(src: Instance) -> Self {
        rpc::Instance {
            id: Some(src.id.into()),
            segment_id: None,
            machine_id: Some(src.machine_id.into()),
            operating_system: None,
            user_data: None,
            custom_ipxe: None,
            ssh_keys: vec![],
            requested: Some(rpc::Timestamp {
                seconds: src.requested.timestamp(),
                nanos: 0,
            }),
            started: Some(rpc::Timestamp {
                seconds: src.started.timestamp(),
                nanos: 0,
            }),
            finished: src.finished.map(|t| rpc::Timestamp {
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
