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

use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::metadata::Metadata;

#[derive(Clone, Debug)]
pub struct VpcPrefix {
    pub id: VpcPrefixId,
    pub vpc_id: VpcId,
    pub config: VpcPrefixConfig,
    pub metadata: Metadata,
    pub status: VpcPrefixStatus,
}

#[derive(Clone, Debug)]
pub struct VpcPrefixConfig {
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
pub struct VpcPrefixStatus {
    pub last_used_prefix: Option<IpNetwork>,
    pub total_31_segments: u32,
    pub available_31_segments: u32,
    pub total_linknet_segments: u64,
    pub available_linknet_segments: u64,
}

impl<'r> sqlx::FromRow<'r, PgRow> for VpcPrefix {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id = row.try_get("id")?;
        let prefix = row.try_get("prefix")?;
        let name = row.try_get("name")?;
        let vpc_id = row.try_get("vpc_id")?;
        let last_used_prefix = row.try_get("last_used_prefix")?;
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;
        let description: String = row.try_get("description")?;

        Ok(VpcPrefix {
            id,
            config: VpcPrefixConfig { prefix },
            metadata: Metadata {
                name,
                description,
                labels: labels.0,
            },
            vpc_id,
            status: VpcPrefixStatus {
                last_used_prefix,
                total_31_segments: 0,
                available_31_segments: 0,
                total_linknet_segments: 0,
                available_linknet_segments: 0,
            },
        })
    }
}

#[derive(Clone, Debug)]
pub enum PrefixMatch {
    Exact(IpNetwork),
    Contains(IpNetwork),
    ContainedBy(IpNetwork),
}

/// NewVpcPrefix represents a VPC prefix resource before it's persisted to the
/// database.
pub struct NewVpcPrefix {
    pub id: VpcPrefixId,
    pub vpc_id: VpcId,
    pub config: VpcPrefixConfig,
    pub metadata: Metadata,
}

pub struct UpdateVpcPrefix {
    pub id: VpcPrefixId,
    // This is all we support updating at the moment. In the future we might
    // also implement prefix resizing, and at that point we'll need to use
    // Option for all the fields.
    pub metadata: Metadata,
}

pub struct DeleteVpcPrefix {
    pub id: VpcPrefixId,
}
