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

use ::rpc::forge as rpc;
use chrono::prelude::*;
use sqlx::{FromRow, Postgres, Transaction};
use std::ops::DerefMut;

use super::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};
use crate::{CarbideError, CarbideResult};
use forge_uuid::domain::DomainId;

const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

/// A DNS domain. Used by carbide-dns for resolving FQDNs.
/// We create an initial one startup. Each segment can have a different domain,
/// including a domain provided by a tenant. In practice we only use a single site-wide
/// domain currently.
///
/// Derived trait sqlx::FromRow consist of a series of calls to
/// [`sqlx::Row::try_get`] using the name from each struct field
#[derive(Clone, Debug, FromRow)]
pub struct Domain {
    /// id is the unique ID of the domain entry
    pub id: DomainId,

    /// domain name e.g. mycompany.com, subdomain.mycompany.com
    pub name: String,

    /// When this domain record was created
    pub created: DateTime<Utc>,

    /// When the domain record was last modified
    pub updated: DateTime<Utc>,

    // when the domain was deleted
    pub deleted: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for crate::db::domain::IdColumn {
    type TableType = Domain;
    type ColumnType = DomainId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct NameColumn;
impl<'a> ColumnInfo<'a> for NameColumn {
    type TableType = Domain;
    type ColumnType = &'a str;

    fn column_name(&self) -> &'static str {
        "name"
    }
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
        match self.persist_inner(txn, query).await {
            Ok(Some(domain)) => Ok(domain),
            Ok(None) => {
                // likely unreachable - needed because persist_inner uses fetch_optional
                Err(CarbideError::NotFoundError {
                    kind: "domain",
                    id: self.name.clone(),
                })
            }
            Err(err) => Err(err),
        }
    }

    /// Create the domain only if it would be the first one
    pub async fn persist_first(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Option<Domain>> {
        let query = "
            INSERT INTO domains (name) SELECT $1
            WHERE NOT EXISTS (SELECT name FROM domains)
            RETURNING *";
        self.persist_inner(txn, query).await
    }

    async fn persist_inner(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        query: &'static str,
    ) -> CarbideResult<Option<Domain>> {
        sqlx::query_as(query)
            .bind(&self.name)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::Database(e)
                    if e.constraint() == Some(SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE) =>
                {
                    CarbideError::InvalidArgument("name".to_string())
                }
                sqlx::Error::Database(e)
                    if e.constraint() == Some(SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX) =>
                {
                    CarbideError::InvalidArgument("name".to_string())
                }
                e => CarbideError::from(DatabaseError::new(file!(), line!(), query, e)),
            })
    }
}

impl Domain {
    /// Finds `domains` based on specified criteria, excluding deleted entries.
    ///
    /// Returns `Vec<Domain>`
    ///
    /// # Arguments
    ///
    /// * [`ObjectColumnFilter`] - An enum that determines the query criteria
    ///
    /// # Examples
    ///
    ///
    pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Domain>>(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<Domain>, DatabaseError> {
        Self::find_all_by(txn, filter, false).await
    }

    /// Similar to [`Domain::find_by`] but lets you specify whether to include deleted results
    pub async fn find_all_by<'a, C: ColumnInfo<'a, TableType = Domain>>(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
        include_deleted: bool,
    ) -> Result<Vec<Domain>, DatabaseError> {
        let mut query = FilterableQueryBuilder::new("SELECT * FROM domains").filter(&filter);
        if !include_deleted {
            query.push(" AND deleted IS NULL");
        }
        query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))
    }

    pub fn new(name: &str) -> Domain {
        Self {
            id: DomainId::from(uuid::Uuid::new_v4()),
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
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> Result<Vec<Self>, DatabaseError> {
        Self::find_by(txn, ObjectColumnFilter::One(NameColumn, &name)).await
    }

    /// Find the domain with the given ID, even if it is deleted.
    pub async fn find_by_uuid(
        txn: &mut Transaction<'_, Postgres>,
        uuid: DomainId,
    ) -> Result<Option<Self>, DatabaseError> {
        Self::find_all_by(txn, ObjectColumnFilter::One(IdColumn, &uuid), true)
            .await
            .map(|f| f.first().cloned())
    }

    pub async fn delete(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Domain, DatabaseError> {
        let query = "UPDATE domains SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(txn.deref_mut())
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
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub fn id(&self) -> &DomainId {
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
