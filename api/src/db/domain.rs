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

use crate::model::RpcDataConversionError;
use ::rpc::forge as rpc;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgHasArrayType, PgTypeInfo};
use sqlx::{FromRow, Postgres, Transaction, Type};
use std::fmt;
use std::str::FromStr;
use tonic::Status;

use super::DatabaseError;
use crate::db::vpc::VpcId;
use crate::{CarbideError, CarbideResult};

const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

/// DomainId is a strongly typed UUID specific to an Infiniband
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc. This
/// is similar to what we do for MachineId, VpcId, InstanceId,
/// NetworkSegmentId, and basically all of the IDs in measured boot.
#[derive(
    Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq, Eq, Hash, Default,
)]
#[sqlx(type_name = "UUID")]
pub struct DomainId(pub uuid::Uuid);

impl From<DomainId> for uuid::Uuid {
    fn from(id: DomainId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for DomainId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for DomainId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("DomainId", input.to_string())
        })?))
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<DomainId> for ::rpc::common::Uuid {
    fn from(val: DomainId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<::rpc::common::Uuid> for DomainId {
    type Error = RpcDataConversionError;
    fn try_from(msg: ::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<&::rpc::common::Uuid> for DomainId {
    type Error = RpcDataConversionError;
    fn try_from(msg: &::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<::rpc::common::Uuid>> for DomainId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<::rpc::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            // TODO(chet): Maybe this isn't the right place for this, since
            // depending on the proto message, the field name can differ (which
            // should actually probably be standardized anyway), or we can just
            // take a similar approach to ::InvalidUuid can say "field of type"?
            return Err(CarbideError::MissingArgument("domain_id").into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl DomainId {
    pub fn from_grpc(msg: Option<::rpc::common::Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad grpc domain ID: {}", e)))
    }
}

impl PgHasArrayType for DomainId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

///
/// A parameter to find() to filter resources by DomainId;
///
#[derive(Clone)]
pub enum DomainIdKeyedObjectFilter<'a> {
    /// Don't filter by DomainId
    All,

    /// Filter by a list of DomainIds
    List(&'a [DomainId]),

    /// Retrieve a single resource
    One(DomainId),
}

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
            .fetch_optional(&mut **txn)
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
        filter: DomainIdKeyedObjectFilter<'_>,
    ) -> Result<Vec<Domain>, DatabaseError> {
        // TODO(jdg):  Add a deleted option to find
        let results: Vec<Domain> = match filter {
            DomainIdKeyedObjectFilter::All => {
                let query = "SELECT * FROM domains WHERE deleted is NULL";
                sqlx::query_as(query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            DomainIdKeyedObjectFilter::One(uuid) => {
                let query = "SELECT * FROM domains WHERE id = $1 AND deleted is NULL";
                sqlx::query_as(query)
                    .bind(uuid)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            DomainIdKeyedObjectFilter::List(list) => {
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
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_vpc(
        txn: &mut Transaction<'_, Postgres>,
        vpc_id: VpcId, // aka projects for now 4/7/2022
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
        name: &str,
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
        uuid: DomainId,
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
