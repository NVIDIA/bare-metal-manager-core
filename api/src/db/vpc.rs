use std::convert::TryFrom;
use std::convert::TryInto;

use chrono::prelude::*;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};
use uuid::Uuid;

use ::rpc::Timestamp;

use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

#[derive(Clone, Debug)]
pub struct Vpc {
    pub id: Uuid,
    pub name: String,
    pub organization_id: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub name: String,
    pub organization: String,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: Uuid,
    pub name: String,
    pub organization: String,
}

#[derive(Clone, Debug)]
pub struct DeleteVpc {
    pub id: Uuid,
}

#[derive(Clone, Debug)]
pub struct VpcSearchQuery {
    pub id: Option<uuid::Uuid>,
    pub string: Option<String>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Vpc {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Vpc {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            organization_id: row.try_get("organization_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

impl NewVpc {
    pub async fn persist(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vpc> {
        Ok(
            sqlx::query_as("INSERT INTO vpcs (name, organization_id) VALUES ($1, $2) RETURNING *")
                .bind(&self.name)
                .bind(&self.organization)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}

impl Vpc {
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<Vpc>> {
        let results: Vec<Vpc> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as("SELECT * FROM vpcs")
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as("SELECT * FROM vpcs WHERE id = $1")
                    .bind(uuid)
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as("select * from vpcs WHERE id = ANY($1)")
                    .bind(list)
                    .fetch_all(&mut *txn)
                    .await?
            }
        };

        Ok(results)
    }
}

impl From<Vpc> for rpc::forge::v0::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::forge::v0::Vpc {
            id: Some(src.id.into()),
            name: src.name,
            organization: src.organization_id,
            created: Some(Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),
            updated: Some(Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),
            deleted: src.deleted.map(|t| Timestamp {
                seconds: t.timestamp(),
                nanos: 0,
            }),
        }
    }
}

impl TryFrom<rpc::forge::v0::Vpc> for NewVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::v0::Vpc) -> Result<Self, Self::Error> {
        if value.id.is_some() {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "VPC",
            )));
        }
        Ok(NewVpc {
            name: value.name,
            organization: value.organization,
        })
    }
}

impl TryFrom<rpc::forge::v0::Vpc> for UpdateVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::v0::Vpc) -> Result<Self, Self::Error> {
        Ok(UpdateVpc {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            name: value.name,
            organization: value.organization,
        })
    }
}

impl TryFrom<rpc::forge::v0::VpcDeletion> for DeleteVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::v0::VpcDeletion) -> Result<Self, Self::Error> {
        Ok(DeleteVpc {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
        })
    }
}

impl From<Vpc> for rpc::forge::v0::VpcDeletionResult {
    fn from(_src: Vpc) -> Self {
        rpc::forge::v0::VpcDeletionResult {}
    }
}

impl UpdateVpc {
    pub async fn update(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vpc> {
        Ok(sqlx::query_as(
            "UPDATE vpcs SET name=$1, organization_id=$2, updated=NOW() WHERE id=$3 RETURNING *",
        )
        .bind(&self.name)
        .bind(&self.organization)
        .bind(&self.id)
        .fetch_one(&mut *txn)
        .await?)
    }
}

impl DeleteVpc {
    pub async fn delete(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vpc> {
        Ok(
            sqlx::query_as("UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *")
                .bind(&self.id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}
