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
use ipnetwork::IpNetwork;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::DatabaseError;

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    record: IpNetwork,
}

#[derive(Default, Debug, Clone, FromRow)]
pub struct DnsResourceRecord {
    record_data: Option<ResourceRecord>,
}

#[derive(Default, Debug, Clone)]
pub struct DnsQuestion {
    pub query_name: Option<String>,
    pub query_type: Option<u32>,
    pub query_class: Option<u32>,
}

#[derive(Default, Debug, Clone)]
pub struct DnsResponse {
    pub resource_records: Vec<DnsResourceRecord>,
    pub response_code: Option<u32>,
}

impl DnsResponse {
    pub fn add_record(&mut self, resource_record: DnsResourceRecord) -> &mut DnsResponse {
        self.resource_records.push(resource_record);
        self
    }

    pub fn with_response_code(&mut self, response_code: u32) -> &mut DnsResponse {
        self.response_code = Some(response_code);
        self
    }
}

impl<'r> FromRow<'r, PgRow> for ResourceRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourceRecord {
            record: row.try_get("resource_record")?,
        })
    }
}

impl From<ResourceRecord> for String {
    fn from(value: ResourceRecord) -> Self {
        value.record.to_string()
    }
}

// Protobuf does not have an IPAddr type, so convert to string
impl From<DnsResourceRecord> for rpc::dns_message::dns_response::Dnsrr {
    fn from(dns: DnsResourceRecord) -> Self {
        rpc::dns_message::dns_response::Dnsrr {
            rdata: dns.record_data.map(|r| r.record.ip().to_string()),
        }
    }
}

impl From<DnsResponse> for rpc::dns_message::DnsResponse {
    fn from(dns: DnsResponse) -> Self {
        rpc::dns_message::DnsResponse {
            rcode: dns.response_code,
            rrs: dns
                .resource_records
                .into_iter()
                .map(|rr| rr.into())
                .collect(),
        }
    }
}

impl DnsQuestion {
    pub async fn find_record(
        txn: &mut Transaction<'_, Postgres>,
        question: DnsQuestion,
    ) -> Result<DnsResponse, DatabaseError> {
        let mut response = DnsResponse::default();

        tracing::info!("{:?}", question);
        match question.query_type {
            Some(1) => {
                let query = "SELECT resource_record from dns_records WHERE q_name=$1 AND family(resource_record) = 4;";
                let result = sqlx::query_as::<_, ResourceRecord>(query)
                    .bind(Some(question.query_name))
                    .fetch_one(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
                tracing::info!("{:?}", result);
                let rr = DnsResourceRecord {
                    record_data: Some(result),
                };
                response.resource_records.push(rr);
                response.response_code = Some(1);
            }
            None => (),
            _ => (),
        };

        Ok(response)
    }
}
