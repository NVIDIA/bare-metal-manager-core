/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use carbide_uuid::domain::DomainId;
use chrono::{DateTime, Utc};
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Error, FromRow, Row};
use tracing::log::debug;

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

impl TryFrom<rpc::Domain> for NewDomain {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::Domain) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
            return Err(RpcDataConversionError::IdentifierSpecifiedForNewObject(
                String::from("Domain"),
            ));
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
}

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
            debug!("DNS serial number incremented: {incremented_serial}");
            self.serial = incremented_serial;
        }
    }
    pub fn generate_new_serial() -> u32 {
        let now = Utc::now();
        let formatted_data = now.format("%Y%m%d").to_string() + "01";
        debug!("Serial generated for zone {formatted_data}");
        formatted_data
            .parse::<u32>()
            .expect("Unable to generate new serial for zone")
    }

    pub fn new(domain_name: &str) -> Soa {
        Soa {
            primary_ns: format!("ns1.{domain_name}"),
            contact: format!("hostmaster.{domain_name}"),
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

impl DomainMetadata {
    pub fn update_allow_axfr_from(&mut self, axfr_list: Vec<String>) {
        self.allow_axfr_from = axfr_list
    }
}

// Marshal Domain object into Protobuf
impl From<Domain> for rpc::Domain {
    fn from(src: Domain) -> Self {
        rpc::Domain {
            id: Some(src.id),
            name: src.name,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
        }
    }
}
