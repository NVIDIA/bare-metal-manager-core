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
use ::rpc::protos;
use db::dns::resource_record;
use dns_record::constants::*;
use dns_record::{DnsResourceRecordReply, DnsResourceRecordType};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

#[derive(Clone, Debug)]
pub struct DnsResourceRecordLookupResponse {
    pub record: Vec<DnsResourceRecordReply>,
}

impl From<DnsResourceRecordLookupResponse> for protos::dns::DnsResourceRecordLookupResponse {
    fn from(value: DnsResourceRecordLookupResponse) -> Self {
        Self {
            records: value.record.into_iter().map(Into::into).collect(),
        }
    }
}

async fn lookup_soa_record(
    db: impl DbReader<'_>,
    query_name: &str,
) -> Result<DnsResourceRecordReply, tonic::Status> {
    tracing::debug!("Looking up SOA record for {}", query_name);
    let record = resource_record::get_soa_record(db, query_name)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "soa_record",
            id: query_name.to_string(),
        })?;
    Ok(DnsResourceRecordReply {
        qtype: DnsResourceRecordType::SOA.to_string(),
        qname: query_name.to_string(),
        ttl: record.0.ttl.0 as u32,
        content: record.0.to_string(),
        domain_id: None,
        scope_mask: None,
        auth: None,
    })
}

/// Returns ALL record types (A, AAAA, CNAME, etc.) - PowerDNS filters to requested type
async fn lookup_records_by_qname(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Vec<DnsResourceRecordReply>, tonic::Status> {
    tracing::debug!("Looking up records for {}", query_name);

    // dns_records view expects trailing dots (FQDN format)
    let qname_with_dot = if !query_name.ends_with('.') {
        format!("{}.", query_name)
    } else {
        query_name.to_string()
    };

    let result = resource_record::find_record(txn, &qname_with_dot)
        .await
        .map_err(CarbideError::from)?
        .into_iter()
        .map(|db_record| {
            let model_record: model::dns::ResourceRecord = db_record.into();
            model_record.into()
        })
        .collect::<Vec<_>>();

    Ok(result)
}

/// Handles ANY DNS record lookups for queries from PowerDNS
///
/// Per PowerDNS backend documentation:
/// **"Backends should do no thinking. Just answer the question, with data or none."**
/// https://blog.powerdns.com/2015/06/23/what-is-a-powerdns-backend-and-how-do-i-make-it-send-an-nxdomain
///
/// # PowerDNS Query Strategy
///
/// PowerDNS may ask ANY queries even when the client asks for specific types (A, AAAA, MX, etc.)
/// This optimization allows PowerDNS to:
/// - Check for CNAMEs and get complete data in one backend query
/// - Cache the results and filter to the requested type
/// - Reduce total backend queries
///
/// # How NXDOMAIN Works
///
/// From PowerDNS docs: To generate NXDOMAIN from your backend:
/// 1. PowerDNS asks for a domain's SOA record → you return it (proves you're authoritative)
/// 2. PowerDNS asks for 'nosuchdomain.yourdomain.com' → you return nothing (empty result)
/// 3. PowerDNS concludes: "I'm authoritative for the zone, but this record doesn't exist" → NXDOMAIN
///
/// # Implementation
///
/// This function:
/// 1. Queries the dns_records view for all matching records (A, AAAA, CNAME, etc.)
/// 2. If the qname matches a domain we're authoritative for, includes the SOA record
/// 3. Returns everything - PowerDNS decides what to include in the final packet
///
async fn lookup_any_record<DB>(
    txn: &mut DB,
    query_name: &str,
) -> Result<Vec<DnsResourceRecordReply>, Status>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let mut dns_records: Vec<DnsResourceRecordReply> = Vec::new();

    tracing::debug!("Looking up ANY records for {}", query_name);

    // 1. Look up all matching records from dns_records view
    //    (Returns A, AAAA, CNAME, etc. - PowerDNS will filter if needed)
    let records = lookup_records_by_qname(&mut *txn, query_name).await?;
    dns_records.extend(records);

    // 2. If this query is for a domain we're authoritative for, also include SOA
    //    domains table stores names without trailing dots
    let domain_name = db::dns::normalize_domain(query_name);
    match db::dns::domain::find_by_name(&mut *txn, &domain_name).await {
        Ok(domains) if !domains.is_empty() => {
            let domain = &domains[0];
            tracing::debug!(
                domain_name = %domain.name,
                "Found authoritative domain for query"
            );

            match lookup_soa_record(txn, &domain.name).await {
                Ok(soa) => {
                    tracing::debug!(
                        domain = %domain.name,
                        "Including SOA record in ANY response"
                    );
                    dns_records.push(soa);
                }
                Err(e) => {
                    tracing::warn!(
                        domain = %domain.name,
                        error = %e,
                        "Failed to lookup SOA record for authoritative domain"
                    );
                }
            }
        }
        Ok(_) => {
            tracing::debug!(
                query_name = %query_name,
                "No authoritative domain found for query - SOA not included"
            );
        }
        Err(e) => {
            tracing::warn!(
                query_name = %query_name,
                error = %e,
                "Error looking up domain by name"
            );
        }
    }

    // Return everything we found - PowerDNS decides what to do with it
    if dns_records.is_empty() {
        tracing::debug!("No DNS records found for query");
    } else {
        tracing::debug!(count = dns_records.len(), "Found DNS records");
        tracing::debug!(
        count=dns_records.len(),
        records=?dns_records,
        "DNS records details"
        );
    }
    Ok(dns_records)
}

pub async fn get_all_domains(
    api: &Api,
    _request: Request<protos::dns::GetAllDomainsRequest>,
) -> Result<Response<protos::dns::GetAllDomainsResponse>, Status> {
    log_request_data(&_request);

    let domains = db::dns::domain::find_by(
        &api.database_connection,
        db::ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;

    tracing::debug!(count = domains.len(), "Found domains");
    for domain in &domains {
        tracing::debug!(
            domain_id = %domain.id,
            domain_name = %domain.name,
            "Domain"
        );
    }

    let result: Vec<protos::dns::DomainInfo> = domains
        .into_iter()
        .map(model::dns::DomainInfo::from)
        .map(protos::dns::DomainInfo::from)
        .collect();

    let response = protos::dns::GetAllDomainsResponse { result };

    tracing::debug!(
        count = response.result.len(),
        "Formatted DomainInfo response"
    );
    Ok(Response::new(response))
}

pub async fn get_all_domain_metadata(
    api: &Api,
    request: Request<protos::dns::DomainMetadataRequest>,
) -> Result<Response<protos::dns::DomainMetadataResponse>, Status> {
    log_request_data(&request);

    let metadata_request = request.into_inner();

    let domain_name = db::dns::normalize_domain(&metadata_request.domain);

    let domains = db::dns::domain::find_by(
        &api.database_connection,
        db::ObjectColumnFilter::<db::dns::domain::NameColumn>::One(
            db::dns::domain::NameColumn,
            &domain_name.as_str(),
        ),
    )
    .await?;

    let domain = domains.first().ok_or_else(|| CarbideError::NotFoundError {
        kind: "domain",
        id: metadata_request.domain.clone(),
    })?;

    let proto_metadata = domain
        .metadata
        .as_ref()
        .map(|m| protos::dns::Metadata::from(m.clone()));

    Ok(Response::new(protos::dns::DomainMetadataResponse {
        result: proto_metadata,
    }))
}
pub async fn lookup_record(
    api: &Api,
    request: Request<protos::dns::DnsResourceRecordLookupRequest>,
) -> Result<Response<protos::dns::DnsResourceRecordLookupResponse>, Status> {
    log_request_data(&request);

    let lookup_request = request.into_inner();

    // Log the full incoming request for debugging
    tracing::debug!(
        qtype = %lookup_request.qtype,
        qname = %lookup_request.qname,
        zone_id = %lookup_request.zone_id,
        "Processing DNS lookup request"
    );

    let rrtype = DnsResourceRecordType::try_from(lookup_request.qtype)
        .map_err(|e| tonic::Status::invalid_argument(format!("Invalid qtype supplied: {}", e)))?;

    let qname = lookup_request.qname;

    if qname.is_empty() {
        return Err(Status::invalid_argument("qname cannot be empty"));
    }

    let resource_record: Vec<DnsResourceRecordReply> = match rrtype {
        DnsResourceRecordType::ANY => {
            // Return ALL records for this qname
            let normalized = db::dns::normalize_domain(&qname);
            lookup_any_record(&mut api.db_reader(), &normalized).await?
        }
        DnsResourceRecordType::SOA => {
            // SOA queries: only return SOA record for the domain
            let normalized = db::dns::normalize_domain(&qname);
            let record = lookup_soa_record(&api.database_connection, &normalized).await?;
            vec![record]
        }
        _ => {
            // For all other types (A, AAAA, MX, CNAME, etc.):
            lookup_records_by_qname(&api.database_connection, &qname).await?
        }
    };

    let resp = DnsResourceRecordLookupResponse {
        record: resource_record,
    };
    Ok(Response::new(resp.into()))
}

// ============================================================================
// LEGACY ADAPTER HANDLER - DEPRECATED
// This handler provides backward compatibility
// Converts legacy DNSMessage format to new DnsResourceRecordLookupRequest
// TODO: Remove this handler after all clients have migrated
// ============================================================================

use ::rpc::forge::dns_message::dns_response::Dnsrr;
use ::rpc::forge::dns_message::{DnsQuestion, DnsResponse};
use db::db_read::DbReader;

/// Compatibility adapter for legacy lookup_record RPC
pub async fn lookup_record_legacy_compat(
    api: &Api,
    request: Request<DnsQuestion>,
) -> Result<Response<DnsResponse>, Status> {
    tracing::info!("Legacy RPC method lookup_record_legacy called");

    let question = request.into_inner();
    let qname = question.q_name.map_or_else(
        || {
            tracing::warn!(
                "Received legacy DNS request with missing q_name - defaulting to empty string"
            );
            "".to_string()
        },
        |name| name,
    );

    let q_type = question.q_type.map_or_else(
        || {
            tracing::warn!("Received legacy DNS request with missing q_type - defaulting to 'A'");
            1
        },
        |qtype| qtype,
    );

    // Log the full incoming request for debugging
    tracing::info!(
        qname = %qname.as_str(),
        q_type,
        q_class = ?question.q_class,
        "Processing legacy DNS lookup request"
    );

    // Check for empty qname early
    if qname.is_empty() {
        tracing::warn!("Received legacy DNS request with empty qname");
        return Err(Status::invalid_argument("qname cannot be empty"));
    }

    // Convert numeric q_type to string using constants
    let qtype = match q_type as u16 {
        DNS_QTYPE_A => DNS_TYPE_A,
        DNS_QTYPE_NS => DNS_TYPE_NS,
        DNS_QTYPE_CNAME => DNS_TYPE_CNAME,
        DNS_QTYPE_SOA => DNS_TYPE_SOA,
        DNS_QTYPE_PTR => DNS_TYPE_PTR,
        DNS_QTYPE_MX => DNS_TYPE_MX,
        DNS_QTYPE_TXT => DNS_TYPE_TXT,
        DNS_QTYPE_AAAA => DNS_TYPE_AAAA,
        DNS_QTYPE_SRV => DNS_TYPE_SRV,
        DNS_QTYPE_ANY => DNS_TYPE_ANY,
        _ => {
            return Err(Status::invalid_argument(format!(
                "Unsupported DNS record type: {}",
                q_type
            )));
        }
    }
    .to_string();

    // Resolve domain from qname
    // Extract the domain part from the FQDN
    let domain_name = if qname.ends_with('.') {
        &qname[..qname.len() - 1]
    } else {
        &qname
    };

    // Try to find the domain this record belongs to
    // Find all domains and match the longest suffix
    let domains = db::dns::domain::find_by(
        &api.database_connection,
        db::ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;

    let domain = domains
        .iter()
        .filter(|d| domain_name.ends_with(&d.name))
        .max_by_key(|d| d.name.len())
        .ok_or_else(|| Status::not_found(format!("No domain found for qname: {}", qname)))?;

    // Convert to new request format
    let lookup_request = protos::dns::DnsResourceRecordLookupRequest {
        qtype,
        qname: qname.clone(),
        zone_id: domain.id.to_string(),
        local: None,
        remote: None,
        real_remote: None,
    };

    // Call the new handler
    let response = lookup_record(api, Request::new(lookup_request)).await?;
    let lookup_response = response.into_inner();

    // Convert new response to legacy format
    let rrs = lookup_response
        .records
        .into_iter()
        .map(|record| Dnsrr {
            rdata: Some(record.content),
        })
        .collect();

    Ok(Response::new(DnsResponse { rrs }))
}
