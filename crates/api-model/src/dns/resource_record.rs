/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Conversion layer for DNS resource records.
//!
//! This module provides conversions from database types to the shared
//! `DnsResourceRecordReply` type from the `dns_record` crate.

use dns_record::DnsResourceRecordReply;

/// Represents a resource record from the database.
///
/// This is a lightweight struct that exists solely for conversion purposes.
/// The actual database type is `db::dns::resource_record::DbResourceRecord`.
pub struct ResourceRecord {
    pub q_type: String,
    pub q_name: String,
    pub ttl: u32,
    pub content: String,
    pub domain_id: Option<String>,
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
