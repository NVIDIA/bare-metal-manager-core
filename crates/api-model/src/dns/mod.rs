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

use ::rpc::errors::RpcDataConversionError;
use chrono::{DateTime, Utc};
use dns_record::SoaRecord;
use serde::{Deserialize, Serialize};

pub mod domain_info;
pub mod metadata;
pub mod resource_record;
pub mod snapshot;

pub use domain_info::DomainInfo;
pub use metadata::DomainMetadata;
pub use resource_record::ResourceRecord;
pub use snapshot::SoaSnapshot;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Domain {
    pub id: carbide_uuid::domain::DomainId,
    pub name: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub soa: Option<SoaSnapshot>,
    pub metadata: Option<DomainMetadata>,
}

impl Domain {
    /// Increments the SOA serial number for this domain.
    /// This should be called before updating the domain in the database
    /// to ensure DNS changes are properly versioned.
    pub fn increment_serial(&mut self) {
        if let Some(ref mut soa_snapshot) = self.soa {
            soa_snapshot.0.increment_serial();
        }
    }

    /// Creates a new SOA record if one doesn't exist, or increments the existing one.
    pub fn ensure_soa_and_increment(&mut self) {
        if self.soa.is_none() {
            self.soa = Some(SoaSnapshot::new(&self.name));
        }
        self.increment_serial();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewDomain {
    pub name: String,
    pub soa: Option<SoaSnapshot>,
}

impl NewDomain {
    /// Creates a new domain with a default SOA record.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            soa: Some(SoaSnapshot::new(&name)),
            name,
        }
    }
}

impl TryFrom<rpc::protos::dns::Domain> for NewDomain {
    type Error = RpcDataConversionError;

    fn try_from(proto: rpc::protos::dns::Domain) -> Result<Self, Self::Error> {
        let soa = proto
            .soa
            .map(|soa| {
                let record: SoaRecord = serde_json::from_str(&soa)
                    .map_err(|e| RpcDataConversionError::InvalidSoaRecord(e.to_string()))?;
                Ok::<SoaSnapshot, RpcDataConversionError>(SoaSnapshot(record))
            })
            .transpose()?;

        Ok(NewDomain {
            name: proto.name,
            soa,
        })
    }
}

impl From<Domain> for rpc::protos::dns::Domain {
    fn from(domain: Domain) -> Self {
        rpc::protos::dns::Domain {
            id: Some(domain.id),
            name: domain.name,
            created: Some(domain.created.into()),
            updated: Some(domain.updated.into()),
            deleted: domain.deleted.map(|d| d.into()),
            metadata: domain.metadata.map(|m| m.into()),
            soa: domain.soa.map(|s| s.0.to_string()),
        }
    }
}

impl TryFrom<rpc::protos::dns::Domain> for Domain {
    type Error = RpcDataConversionError;

    fn try_from(domain: rpc::protos::dns::Domain) -> Result<Self, Self::Error> {
        let domain_id = match domain.id {
            Some(id) => id,
            None => uuid::Uuid::new_v4().into(),
        };

        let created = match domain.created {
            Some(created) => {
                let system_time = std::time::SystemTime::try_from(created)
                    .map_err(|_| RpcDataConversionError::InvalidTimestamp(created.to_string()))?;
                DateTime::<Utc>::from(system_time)
            }
            None => Utc::now(),
        };

        let updated = match domain.updated {
            Some(updated) => {
                let system_time = std::time::SystemTime::try_from(updated)
                    .map_err(|_| RpcDataConversionError::InvalidTimestamp(updated.to_string()))?;
                DateTime::<Utc>::from(system_time)
            }
            None => Utc::now(),
        };

        let deleted: Option<DateTime<Utc>> = match domain.deleted {
            Some(deleted) => {
                let system_time = std::time::SystemTime::try_from(deleted)
                    .map_err(|_| RpcDataConversionError::InvalidTimestamp(deleted.to_string()))?;
                Some(DateTime::<Utc>::from(system_time))
            }
            None => None,
        };

        let soa: Option<SoaSnapshot> = domain
            .soa
            .map(|soa| {
                let record: SoaRecord = serde_json::from_str(&soa)
                    .map_err(|e| RpcDataConversionError::InvalidSoaRecord(e.to_string()))?;
                Ok::<SoaSnapshot, RpcDataConversionError>(SoaSnapshot(record))
            })
            .transpose()?;

        let metadata = domain.metadata.map(DomainMetadata::from);

        Ok(Domain {
            id: domain_id,
            name: domain.name,
            created,
            updated,
            deleted,
            soa,
            metadata,
        })
    }
}
