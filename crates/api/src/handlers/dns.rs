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
use db::db_read::DbReader;
use db::dns::resource_record;
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
        .map_err(|e| CarbideError::InvalidArgument(format!("Invalid qtype supplied: {}", e)))?;

    let qname = lookup_request.qname;

    if qname.is_empty() {
        return Err(CarbideError::InvalidArgument("qname cannot be empty".to_string()).into());
    }

    let resource_record: Vec<DnsResourceRecordReply> = match rrtype {
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
