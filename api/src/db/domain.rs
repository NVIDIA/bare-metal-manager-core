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

use super::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};
use crate::{CarbideError, CarbideResult};
use ::rpc::forge as rpc;
use chrono::prelude::*;
use forge_uuid::domain::DomainId;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Error, FromRow, Postgres, Row, Transaction};
use std::ops::DerefMut;
use tracing::log::debug;

const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

/// Represents a Start of Authority (SOA) record for a DNS zone.
///
/// The SOA record specifies authoritative information about a DNS zone,
/// including primary nameserver, email contact, and zone update details.
/// It is a critical component in DNS configuration, as it defines zone
/// refresh intervals and update policies.
///
/// # Fields
///
/// * `primary_ns` - The primary nameserver responsible for the zone.
/// * `contact` - The email contact for the zone administrator, typically in the format `hostmaster.example.com`.
/// * `serial` - The serial number for the zone, used to track updates. This should be incremented each time the zone file is modified.
/// * `refresh` - The time (in seconds) a secondary nameserver should wait before querying for zone updates.
/// * `retry` - The time (in seconds) a secondary nameserver should wait before retrying a failed zone update query.
/// * `expire` - The time (in seconds) after which a secondary nameserver should discard the zone if no updates are received.
/// * `minimum` - The minimum TTL (time-to-live) value applied to all resource records in the zone. This specifies how long DNS resolvers should cache data from this zone.
/// * `ttl` - The default TTL (time-to-live) value for the SOA record itself, which is the time period for which DNS clients can cache the SOA record.
///
/// # Example
///
/// ```ignore
/// use crate::db::domain::Soa;
/// let soa = Soa {
///     primary_ns: "ns1.example.com".to_string(),
///     contact: "hostmaster.example.com".to_string(),
///     serial: 2024110401,
///     refresh: 3600,
///     retry: 600,
///     expire: 604800,
///     minimum: 3600,
///     ttl: 3600,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soa {
    /// The primary nameserver responsible for the DNS zone.
    pub primary_ns: String,
    /// The contact email address of the zone administrator.
    /// Typically formatted as `hostmaster.example.com`.
    pub contact: String,
    /// The serial number for the zone. Increment this number
    /// with each change to the zone to notify secondaries.
    pub serial: u32,
    /// The time interval (in seconds) for a secondary server to refresh the zone.
    pub refresh: i32,
    /// The retry interval (in seconds) for a secondary server to retry
    /// if a zone refresh fails.
    pub retry: i32,
    /// The expiration time (in seconds) for the zone data on a secondary server.
    /// If no refresh occurs within this time, the zone is considered expired.
    pub expire: i32,
    /// The minimum TTL (time-to-live) value for all records in the zone, indicating
    /// how long resolvers should cache records in the absence of specific TTL settings.
    pub minimum: i32,
    /// The default TTL (time-to-live) for the SOA record itself.
    pub ttl: i32,
}

impl Soa {
    pub fn increment_serial(&mut self) {
        let now = Utc::now();

        // Convert serial to string and strip the last two characters
        let serial_str = self.serial.to_string();
        let stripped_date = &serial_str[..serial_str.len() - 2];

        // Parse the stripped date to check if it's outdated
        let serial_date = stripped_date
            .parse::<u32>()
            .unwrap_or(Self::generate_new_serial());

        let current_date_str = now.format("%Y%m%d").to_string();
        let current_date = current_date_str.parse::<u32>().unwrap_or(0);

        // Check if serial date is outdated
        if serial_date < current_date {
            // Generate a new serial for the new day in `YYYYMMDD01` format
            debug!("DNS serial number is for a different date, generating a new one");
            self.serial = Self::generate_new_serial();
        } else {
            // Increment the last two digits if the date hasn't changed
            let incremented_serial = self.serial + 1;
            debug!("DNS serial number incremented: {}", incremented_serial);
            self.serial = incremented_serial;
        }
    }
    pub fn generate_new_serial() -> u32 {
        let now = Utc::now();
        let formatted_data = now.format("%Y%m%d").to_string() + "01";
        debug!("Serial generated for zone {}", formatted_data);
        formatted_data
            .parse::<u32>()
            .expect("Unable to generate new serial for zone")
    }

    pub fn new(domain_name: &str) -> Soa {
        Soa {
            primary_ns: format!("ns1.{}", domain_name),
            contact: format!("hostmaster.{}", domain_name),
            serial: Self::generate_new_serial(),
            refresh: 3600,
            retry: 3600,
            expire: 604800,
            minimum: 3600,
            ttl: 3600,
        }
    }
}
/// Represents metadata associated with a DNS domain.
///
/// This struct holds additional configuration information for a DNS domain,
/// such as which IP addresses or networks are allowed to perform AXFR (zone transfer) requests.
///
/// # Fields
///
/// * `allow_axfr_from` - A list of IP addresses or CIDR ranges as strings that are permitted to perform AXFR (zone transfer) requests.
///   This can be used to restrict zone transfers to trusted servers.
///
/// A list of IP addresses or CIDR ranges allowed to perform AXFR (zone transfer) requests.
///
/// This provides control over which external servers are permitted to retrieve
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub struct DomainMetadata {
    allow_axfr_from: Vec<String>,
}

#[test]
fn test_domain_metadata() {
    use crate::db::domain::DomainMetadata;
    let mut domain_metadata = DomainMetadata::default();
    domain_metadata
        .update_allow_axfr_from(vec!["192.168.1.1".to_string(), "10.0.0.0/24".to_string()]);
}

impl DomainMetadata {
    pub fn update_allow_axfr_from(&mut self, axfr_list: Vec<String>) {
        self.allow_axfr_from = axfr_list
    }
}

/// A DNS domain. Used by carbide-dns for resolving FQDNs.
/// We create an initial one startup. Each segment can have a different domain,
/// including a domain provided by a tenant. In practice we only use a single site-wide
/// domain currently.
///
/// Derived trait sqlx::FromRow consist of a series of calls to
/// [`sqlx::Row::try_get`] using the name from each struct field
#[derive(Clone, Debug)]
pub struct Domain {
    /// id is the unique ID of the domain entry
    pub id: DomainId,

    /// domain name e.g. mycompany.com, subdomain.mycompany.com
    pub name: String,

    /// When this domain record was created
    pub created: DateTime<Utc>,

    /// When the domain record was last modified
    pub updated: DateTime<Utc>,

    /// when the domain was deleted
    pub deleted: Option<DateTime<Utc>>,

    /// SOA record for this domain
    pub soa: Option<Soa>,

    /// Domain metadata
    pub metadata: Option<DomainMetadata>,
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

impl<'r> FromRow<'r, PgRow> for Domain {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let soa: Option<sqlx::types::Json<Soa>> = row.try_get("soa").ok();
        let metadata: Option<sqlx::types::Json<DomainMetadata>> = row.try_get("metadata").ok();

        Ok(Domain {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: None,
            soa: soa.map(|json| json.0),
            metadata: metadata.map(|json| json.0),
        })
    }
}
pub struct NewDomain {
    pub name: String,
    pub soa: Soa,
    // pub metadata: DomainMetadata, // unused
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

        Ok(NewDomain {
            name: value.name.clone(),
            soa: Soa::new(value.name.as_str()),
        })
    }
}

impl NewDomain {
    pub fn new(name: &str) -> NewDomain {
        Self {
            name: name.to_string(),
            soa: Soa::new(name),
        }
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Domain> {
        let query = "INSERT INTO domains (name, soa) VALUES ($1, $2) returning *";
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
            .bind(sqlx::types::Json(&self.soa))
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
            soa: Some(Soa::new(name)),
            metadata: Some(DomainMetadata::default()),
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
        let soa = Soa::new(&self.name);
        let query = "INSERT INTO domains (name, soa) VALUES ($1, $2) RETURNING name";
        sqlx::query_as(query)
            .bind(&self.name)
            .bind(sqlx::types::Json(&soa))
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
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Domain, DatabaseError> {
        let query = "UPDATE domains SET name=$1, updated=NOW(), soa=$2, metadata=$3 WHERE id=$4 RETURNING *";

        if let Some(ref mut record) = self.soa {
            record.increment_serial();
        }

        sqlx::query_as(query)
            .bind(&self.name)
            .bind(sqlx::types::Json(&self.soa))
            .bind(sqlx::types::Json(&self.metadata))
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

    pub fn soa(self) -> Option<Soa> {
        self.soa
    }

    pub fn metadata(self) -> Option<DomainMetadata> {
        self.metadata
    }
}

#[cfg(test)]
#[test]
fn test_generate_domain_serial_format() {
    // Expected serial format
    let now = Utc::now();
    let expected_serial = now.format("%Y%m%d01").to_string().parse::<u32>().unwrap();

    // Call the function that generates the serial
    let serial = Soa::generate_new_serial();

    assert_eq!(serial, expected_serial);
}
