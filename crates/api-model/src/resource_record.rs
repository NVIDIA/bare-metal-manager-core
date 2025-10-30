/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::IpAddr;

use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

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

impl From<ResourceRecord> for rpc::forge::dns_message::dns_response::Dnsrr {
    fn from(rr: ResourceRecord) -> Self {
        rpc::forge::dns_message::dns_response::Dnsrr {
            rdata: Some(rr.record.to_string()),
        }
    }
}
