use std::convert::{TryFrom, TryInto};

use chrono::prelude::*;
use sqlx::{Error, Postgres, Row};
use sqlx::postgres::PgRow;
use uuid::Uuid;

use ::rpc::Timestamp;
use rpc::forge::v0 as rpc;

use crate::{CarbideError, CarbideResult};

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
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct UpdateInstanceType {
    pub id: Uuid,
    pub short_name: String,
    pub description: String,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct DeactivateInstanceType {
    pub id: Uuid,
}

impl TryFrom<rpc::InstanceType> for NewInstanceType {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceType) -> Result<Self, Self::Error> {
        if value.id.is_some() {
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

impl TryFrom<rpc::InstanceType> for UpdateInstanceType {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceType) -> Result<Self, Self::Error> {
        Ok(UpdateInstanceType {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            short_name: value.short_name,
            description: value.description,
            active: value.active,
        })
    }
}

impl TryFrom<rpc::InstanceTypeDeletion> for DeactivateInstanceType {
    type Error = CarbideError;

    fn try_from(value: rpc::InstanceTypeDeletion) -> Result<Self, Self::Error> {
        Ok(DeactivateInstanceType {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
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
            created: Some(Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),
            updated: Some(Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),
        }
    }
}

impl From<InstanceType> for rpc::InstanceTypeDeletionResult {
    fn from(_src: InstanceType) -> Self {
        rpc::InstanceTypeDeletionResult {}
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

impl UpdateInstanceType {
    pub async fn update(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<InstanceType> {
        Ok(sqlx::query_as("UPDATE instance_types SET short_name=$1, description=$2, active=$3, updated=now() WHERE id=$4 RETURNING *")
            .bind(&self.short_name)
            .bind(&self.description)
            .bind(&self.active)
            .bind(&self.id)
            .fetch_one(&mut *txn).await?)
    }
}

impl DeactivateInstanceType {
    pub async fn deactivate(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<InstanceType> {
        Ok(sqlx::query_as(
            "UPDATE instance_types SET active=false, updated=now() WHERE id=$1 RETURNING *",
        )
            .bind(&self.id)
            .fetch_one(&mut *txn)
            .await?)
    }
}
