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

use std::collections::HashMap;

use dns_record::DnsResourceRecordType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PdnsRequest {
    pub method: String,
    pub parameters: HashMap<String, Value>,
}

impl TryFrom<&PdnsRequest> for rpc::protos::dns::DomainMetadataRequest {
    type Error = eyre::Report;

    fn try_from(request: &PdnsRequest) -> Result<Self, Self::Error> {
        let domain = request
            .parameters
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::error!(
                    method = %request.method,
                    parameters = ?request.parameters,
                    "Missing or invalid 'name' parameter in DomainMetadataRequest"
                );
                eyre::eyre!("Missing or invalid 'domain' parameter")
            })?
            .to_string();

        tracing::trace!(
            method = %request.method,
            domain = %domain,
            "Converted PdnsRequest to DomainMetadataRequest"
        );

        Ok(rpc::protos::dns::DomainMetadataRequest { domain })
    }
}
impl TryFrom<&PdnsRequest> for rpc::protos::dns::GetAllDomainsRequest {
    type Error = eyre::Report;

    fn try_from(request: &PdnsRequest) -> Result<Self, Self::Error> {
        tracing::trace!(
            method = %request.method,
            "Converted PdnsRequest to GetAllDomainsRequest"
        );
        Ok(rpc::protos::dns::GetAllDomainsRequest {})
    }
}

/// Converts a `PdnsRequest` into a `DnsResourceRecordLookupRequest`.
///
/// This conversion is used to handle DNS lookup requests from PowerDNS, typically
/// initiated by DNS clients (e.g., `dig` or `nslookup`). The request is validated
/// and transformed into a format that can be submitted to `carbide-api`.
///
impl TryFrom<&PdnsRequest> for rpc::protos::dns::DnsResourceRecordLookupRequest {
    type Error = eyre::Report;

    fn try_from(request: &PdnsRequest) -> Result<Self, Self::Error> {
        let qtype = request
            .parameters
            .get("qtype")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::error!(
                    method = %request.method,
                    parameters = ?request.parameters,
                    "Missing 'qtype' parameter in DnsResourceRecordLookupRequest"
                );
                eyre::eyre!("Missing qtype parameter")
            })?;

        let real_qtype = DnsResourceRecordType::try_from(qtype).map_err(|e| {
            tracing::error!(
                method = %request.method,
                qtype = %qtype,
                error = %e,
                "Invalid 'qtype' parameter in DnsResourceRecordLookupRequest"
            );
            eyre::eyre!("Invalid 'qtype' parameter: {}", e)
        })?;

        let qname = request
            .parameters
            .get("qname")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tracing::error!(
                    method = %request.method,
                    parameters = ?request.parameters,
                    "Missing or invalid 'qname' parameter in DnsResourceRecordLookupRequest"
                );
                eyre::eyre!("Missing or invalid 'qname' parameter")
            })?
            .to_string();

        if qname.is_empty() {
            tracing::error!(
                method = %request.method,
                "Empty 'qname' parameter in DnsResourceRecordLookupRequest"
            );
            return Err(eyre::eyre!("'qname' parameter cannot be empty"));
        }

        // zone-id can be sent as an integer (-1) or string, or omitted entirely
        // PowerDNS remote backend uses -1 when zone is unknown
        let zone_id = request
            .parameters
            .get("zone-id")
            .and_then(|v| {
                // Handle both string and integer values
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|i| i.to_string()))
            })
            .unwrap_or_else(|| "-1".to_string());

        let local = request
            .parameters
            .get("local")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let remote = request
            .parameters
            .get("remote")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let real_remote = request
            .parameters
            .get("real_remote")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        tracing::trace!(
            method = %request.method,
            qname = %qname,
            qtype = %real_qtype,
            zone_id = %zone_id,
            local = ?local,
            remote = ?remote,
            real_remote = ?real_remote,
            "Converted PdnsRequest to DnsResourceRecordLookupRequest"
        );

        // Construct the Protobuf request
        Ok(rpc::protos::dns::DnsResourceRecordLookupRequest {
            qtype: real_qtype.into(),
            qname,
            zone_id,
            local,
            remote,
            real_remote,
        })
    }
}
