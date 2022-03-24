use crate::{CarbideError, CarbideResult};
use chrono::prelude::*;
use rpc::v0 as rpc;
use sqlx::types::uuid;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use std::convert::TryFrom;
use uuid::Uuid;

const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

/// Domain
/// Dervied trait sqlx::FromRow consist of a series of calls to
/// [`Row::try_get`] using the name from each struct field
#[derive(Clone, Debug)]
pub struct Domain {
    /// Uuid is use
    id: uuid::Uuid,
    /// domain name e.g. mycompany.com, subdomain.mycompany.com
    name: String,

    /// When this domain record was created
    created: DateTime<Utc>,

    /// When the domain record was last modified
    updated: DateTime<Utc>,
}

pub struct NewDomain {
    pub name: String,
}

pub struct UpdateDomain {
    pub name: String,
    pub updated: DateTime<Utc>,
}

// Marshal Domain object into Probobuf
impl From<Domain> for rpc::Domain {
    fn from(src: Domain) -> Self {
        rpc::Domain {
            id: Some(src.id.into()),
            name: src.name,

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

impl TryFrom<rpc::Domain> for NewDomain {
    type Error = CarbideError;

    fn try_from(value: rpc::Domain) -> Result<Self, Self::Error> {
        if let Some(id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Domain",
            )));
        }

        Ok(NewDomain { name: value.name })
    }
}

// Marshal Domain object from Row
impl<'r> sqlx::FromRow<'r, PgRow> for Domain {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Domain {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}

impl NewDomain {
    pub fn new(name: &str) -> NewDomain {
        Self {
            name: name.to_string(),
        }
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Domain> {
        Ok(
            sqlx::query_as("INSERT INTO domains (name) VALUES ($1) returning *")
                .bind(&self.name)
                .fetch_one(&mut *txn)
                .await
                .map_err(|err: sqlx::Error| match err {
                    sqlx::Error::Database(e)
                        if e.constraint() == Some(SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE) =>
                    {
                        CarbideError::InvalidDomainName(String::from(&self.name))
                    }
                    sqlx::Error::Database(e)
                        if e.constraint() == Some(SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX) =>
                    {
                        CarbideError::InvalidDomainName(String::from(&self.name))
                    }
                    _ => CarbideError::from(err),
                })?,
        )
    }
}

impl UpdateDomain {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Domain> {
        todo!()
    }
}

impl Domain {
    pub fn new(name: &str) -> Domain {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created: Utc::now(),
            updated: Utc::now(),
        }
    }

    /// Create a new Domain object in database
    ///
    /// Arguments:
    /// * `txn` - A reference to a currently open database transaction
    /// * `name` - The name of the Domain. e.g. mydomain.com
    ///
    pub async fn create(&self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("INSERT INTO domains (name) VALUES ($1) RETURNING name")
                .bind(&self.name)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: String,
    ) -> CarbideResult<Option<Self>> {
        let mut results: Vec<Domain> = sqlx::query_as("SELECT * FROM domains WHERE name = $1")
            .bind(&name)
            .fetch_all(&mut *txn)
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(results.remove(0))),
            _ => Err(CarbideError::DuplicateDomain(name)),
        }
    }

    // TODO make this work
    pub async fn find_by_uuid(
        txn: &mut Transaction<'_, Postgres>,
        uuid: Uuid,
    ) -> CarbideResult<Option<Self>> {
        todo!()
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        uuid: Uuid,
    ) -> CarbideResult<Option<Self>> {
        todo!()
    }

    pub async fn update(
        txn: &mut Transaction<'_, Postgres>,
        uuid: Uuid,
    ) -> CarbideResult<Option<Self>> {
        todo!()
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created(&self) -> chrono::DateTime<Utc> {
        self.created
    }

    pub fn updated(&self) -> chrono::DateTime<Utc> {
        self.updated
    }
}

#[cfg(test)]
mod tests {}
