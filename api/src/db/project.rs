use crate::{CarbideError, CarbideResult};
use sqlx::postgres::PgRow;
use sqlx::{Error, Postgres, Row, Transaction};
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;

use chrono::prelude::*;

use rpc::v0 as rpc;

#[derive(Clone, Debug)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub organization_id: Option<Uuid>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NewProject {
    pub name: String,
    pub organization: Option<Uuid>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Project {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Project {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            organization_id: row.try_get("organization_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}

impl NewProject {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Project> {
        Ok(sqlx::query_as("INSERT INTO projects (name, organization_id, created, updated) VALUES ($1, $2, now(), now()) RETURNING *")
            .bind(&self.name)
            .bind(&self.organization)
            .fetch_one(&mut *txn).await?)
    }
}

impl From<Project> for rpc::Project {
    fn from(src: Project) -> Self {
        rpc::Project {
            id: Some(src.id.into()),
            name: src.name,
            organization: src.organization_id.map(rpc::Uuid::from),
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

impl TryFrom<rpc::Project> for NewProject {
    type Error = CarbideError;

    fn try_from(value: rpc::Project) -> Result<Self, Self::Error> {
        if let Some(_) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Project",
            )));
        }
        Ok(NewProject {
            name: value.name,
            organization: match value.organization {
                Some(v) => Some(uuid::Uuid::try_from(v)?),
                None => None,
            },
        })
    }
}
