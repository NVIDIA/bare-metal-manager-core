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

//! Conversion layer for DNS resource records.
//!
//! This module provides conversions from database types to the shared
//! `DnsResourceRecordReply` type from the `dns_record` crate.

use dns_record::{DnsResourceRecordReply, DnsResourceRecordType, SoaRecord};

use super::zone::Fqdn;

/// Represents a resource record from the database.
///
/// This is a lightweight struct that exists solely for conversion purposes.
/// The actual database type is `db::dns::resource_record::DbResourceRecord`.
#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub q_type: String,
    pub q_name: String,
    pub ttl: u32,
    pub content: String,
    pub domain_id: Option<String>,
}

impl ResourceRecord {
    /// A zone's SOA published at its apex. `domain_id` is `None`: the SOA is
    /// synthesised from the zone, not read from a record row.
    pub fn soa(zone: &Fqdn, soa: &SoaRecord) -> Self {
        Self {
            q_type: DnsResourceRecordType::SOA.to_string(),
            q_name: zone.to_string(),
            ttl: soa.ttl.0 as u32,
            content: soa.to_string(),
            domain_id: None,
        }
    }
}

impl From<ResourceRecord> for DnsResourceRecordReply {
    fn from(r: ResourceRecord) -> Self {
        Self {
            qtype: r.q_type,
            qname: r.q_name,
            ttl: r.ttl,
            content: r.content,
            domain_id: r.domain_id,
            scope_mask: None,
            auth: None,
        }
    }
}
