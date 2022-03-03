use crate::{CarbideError, CarbideResult};
use sqlx::{Row, Postgres, Transaction, postgres::PgRow};
use uuid::Uuid;
use sqlx::types::uuid;
use chrono::prelude::*;

use rpc::v0 as rpc;


/// Domain 
/// Dervied trait sqlx::FromRow consist of a series of calls to
/// [`Row::try_get`] using the name from each struct field
#[derive(Clone, Debug)]
pub struct Domain {
    /// Uuid is use
    id: Option<uuid::Uuid>,
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

// Marshal Domain object into Probobuf
impl From<Domain> for rpc::Domain {
    fn from(domain: Domain) -> Self {
        todo!()
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
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Domain> {
    Ok(sqlx::query_as("INSERT INTO domains (name) VALUES ($1) returning *")
    .bind(&self.name)
    .fetch_one(&mut *txn)
    .await?)
    }

}

impl Domain {

    pub fn new(name: &str) -> Self {
        let created_time: chrono::DateTime<Utc> = Utc::now();
            Self{
               id: Some(uuid::Uuid::new_v4()),
               name: name.to_string(),
               created: created_time,
               updated: created_time,
            }
     }

    /// Create a new Domain object in database
    /// 
    /// Arguments:
    /// * `txn` - A reference to a currently open database transaction
    /// * `name` - The name of the Domain. e.g. mydomain.com
    /// 
    pub async fn create(&self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<Self> {
        Ok(sqlx::query_as("INSERT INTO domain (name) VALUES ($1) RETURNING name")
            .bind(&self.name)
            .fetch_one(&mut *txn)
            .await?)
            
    }

    pub async fn find(
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

    pub fn id(&self) -> Option<&uuid::Uuid> {
        self.id.as_ref()
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

