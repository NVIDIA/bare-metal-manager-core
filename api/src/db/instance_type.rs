use crate::{CarbideError, CarbideResult};
use sqlx::postgres::PgRow;
use sqlx::{Error, Postgres, Row};
use std::convert::TryFrom;
use uuid::Uuid;

use chrono::prelude::*;

use rpc::v0 as rpc;

#[derive(Clone, Debug)]
pub struct InstanceType {
    pub id: Uuid,
    pub short_name: String,
    pub description: String,
    // todo(baz): Add instance type capabilities enum
    pub active: bool,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for InstanceType {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        Ok(InstanceType {
            id: row.try_get("id")?,
            short_name: row.try_get("short_name")?,
            description: row.try_get("description")?,
            active: row.try_get("active")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NewInstanceType {
    pub short_name: String,
    pub description: String,
    pub active: bool
}

impl TryFrom<rpc::InstanceType> for NewInstanceType {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceType) -> Result<Self, Self::Error> {
        if let Some(id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Instance Type",
            )));
        }
        Ok(NewInstanceType {
            short_name: value.short_name,
            description: value.description,
            active: value.active,
        })
    }
}

impl From<InstanceType> for rpc::InstanceType {
    fn from(src: InstanceType) -> Self {
        rpc::InstanceType {
            id: Some(src.id.into()),
            short_name: src.short_name,
            description: src.description,
            capabilities: vec![0],
            active: src.active,
            created: Some(rpc::Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),
            updated: Some(rpc::Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),

        }
    }
}

impl NewInstanceType {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<InstanceType> {
        Ok(sqlx::query_as("INSERT INTO instance_types (short_name, description, active, created, updated) VALUES ($1, $2, $3, now(), now()) RETURNING *")
            .bind(&self.short_name)
            .bind(&self.description)
            .bind(&self.active)
            .fetch_one(&mut *txn).await?)
    }
}