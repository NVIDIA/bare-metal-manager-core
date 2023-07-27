/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::convert::TryFrom;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use sqlx::types::uuid;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::DatabaseError;
use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

/// Domain
/// Derived trait sqlx::FromRow consist of a series of calls to
/// [`Row::try_get`] using the name from each struct field
#[derive(Clone, Debug, FromRow)]
pub struct Domain {
    /// Uuid is use
    pub id: Uuid,
    /// domain name e.g. mycompany.com, subdomain.mycompany.com
    pub name: String,

    /// When this domain record was created
    pub created: DateTime<Utc>,

    /// When the domain record was last modified
    pub updated: DateTime<Utc>,

    // when the domain was deleted
    pub deleted: Option<DateTime<Utc>>,
}

pub struct NewDomain {
    pub name: String,
}

// Marshal Domain object into Protobuf
impl From<Domain> for rpc::Domain {
    fn from(src: Domain) -> Self {
        rpc::Domain {
            id: Some(src.id.into()),
            name: src.name,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
        }
    }
}

impl TryFrom<rpc::Domain> for NewDomain {
    type Error = CarbideError;

    fn try_from(value: rpc::Domain) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Domain",
            )));
        }

        Ok(NewDomain { name: value.name })
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
        let query = "INSERT INTO domains (name) VALUES ($1) returning *";
        sqlx::query_as(query)
            .bind(&self.name)
            .fetch_one(&mut **txn)
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
                e => CarbideError::from(DatabaseError::new(file!(), line!(), query, e)),
            })
    }
}

impl Domain {
    /// Finds a  `domains` based on UUID
    ///
    /// Returns `Vec<Domain>`
    ///
    /// # Arguments
    ///
    /// * `UUIDKeyedObjectFilter` - An enum that determines the number of `UUID` to use in the query
    ///
    /// # Examples
    ///
    ///
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<Domain>, DatabaseError> {
        // TODO(jdg):  Add a deleted option to find
        let results: Vec<Domain> = match filter {
            UuidKeyedObjectFilter::All => {
                let query = "SELECT * FROM domains WHERE deleted is NULL";
                sqlx::query_as(query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                let query = "SELECT * FROM domains WHERE id = $1 AND deleted is NULL";
                sqlx::query_as(query)
                    .bind(uuid)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::List(list) => {
                let query = "select * from domains WHERE id = ANY($1) AND deleted is NULL";
                sqlx::query_as(query)
                    .bind(list)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
        };

        Ok(results)
    }

    pub fn new(name: &str) -> Domain {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created: Utc::now(),
            updated: Utc::now(),
            deleted: None,
        }
    }

    /// Create a new Domain object in database
    ///
    /// Arguments:
    /// * `txn` - A reference to a currently open database transaction
    /// * `name` - The name of the Domain. e.g. mydomain.com
    ///
    pub async fn create(&self, txn: &mut Transaction<'_, Postgres>) -> Result<Self, DatabaseError> {
        let query = "INSERT INTO domains (name) VALUES ($1) RETURNING name";
        sqlx::query_as(query)
            .bind(&self.name)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_vpc(
        txn: &mut Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid, // aka projects for now 4/7/2022
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM domains where project_id = $1";
        let results: Vec<Self> = sqlx::query_as(query)
            .bind(vpc_id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(results)
    }

    pub async fn find_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: String,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM domains WHERE name= $1 and deleted is NULL";
        sqlx::query_as(query)
            .bind(name)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
    pub async fn find_by_uuid(
        txn: &mut Transaction<'_, Postgres>,
        uuid: Uuid,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = "SELECT * FROM domains WHERE id = $1::uuid";
        sqlx::query_as(query)
            .bind(uuid)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn delete(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Domain, DatabaseError> {
        let query = "UPDATE domains SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Domain, DatabaseError> {
        let query = "UPDATE domains SET name=$1, updated=NOW() WHERE id=$2 RETURNING *";
        sqlx::query_as(query)
            .bind(&self.name)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
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
