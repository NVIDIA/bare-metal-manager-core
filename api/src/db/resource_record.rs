use std::net::IpAddr;

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
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use super::DatabaseError;

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    record: IpAddr,
}

impl<'r> FromRow<'r, PgRow> for ResourceRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourceRecord {
            record: row.try_get("resource_record")?,
        })
    }
}

impl From<ResourceRecord> for rpc::dns_message::dns_response::Dnsrr {
    fn from(rr: ResourceRecord) -> Self {
        rpc::dns_message::dns_response::Dnsrr {
            rdata: Some(rr.record.to_string()),
        }
    }
}

pub async fn find_record(
    txn: &mut PgConnection,
    query_name: &str,
) -> Result<Option<ResourceRecord>, DatabaseError> {
    let query =
        "SELECT resource_record from dns_records WHERE q_name=$1 AND family(resource_record) = 4";
    let result = sqlx::query_as::<_, ResourceRecord>(query)
        .bind(query_name)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(result)
}
