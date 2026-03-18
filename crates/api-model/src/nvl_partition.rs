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

use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId, NvLinkPartitionId};
use chrono::{DateTime, Utc};
use rpc::errors::RpcDataConversionError;
use rpc::forge as rpc_forge;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

#[derive(Clone, Debug, Default)]
pub struct NvLinkPartitionSearchFilter {
    pub tenant_organization_id: Option<String>,
    pub name: Option<String>,
}

impl From<rpc_forge::NvLinkPartitionSearchFilter> for NvLinkPartitionSearchFilter {
    fn from(filter: rpc_forge::NvLinkPartitionSearchFilter) -> Self {
        NvLinkPartitionSearchFilter {
            tenant_organization_id: filter.tenant_organization_id,
            name: filter.name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewNvlPartition {
    pub id: NvLinkPartitionId,
    pub name: NvlPartitionName,
    pub logical_partition_id: NvLinkLogicalPartitionId,
    pub domain_uuid: NvLinkDomainId,
    pub nmx_m_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvlPartitionStatus {
    pub partition: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, sqlx::Type, sqlx::FromRow)]
pub struct NvlPartitionName(String);

impl NvlPartitionName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for NvlPartitionName {
    type Error = RpcDataConversionError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(NvlPartitionName(value))
    }
}

impl From<NvlPartitionName> for String {
    fn from(value: NvlPartitionName) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct NvlPartition {
    pub id: NvLinkPartitionId,
    pub nmx_m_id: String,
    pub domain_uuid: NvLinkDomainId,
    pub name: NvlPartitionName,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
}

/// Returns whether the NvLink partition was deleted
pub fn is_marked_as_deleted(partition: &NvlPartition) -> bool {
    partition.deleted.is_some()
}

impl TryFrom<NvlPartition> for rpc_forge::NvLinkPartition {
    type Error = RpcDataConversionError;
    fn try_from(src: NvlPartition) -> Result<Self, Self::Error> {
        Ok(rpc_forge::NvLinkPartition {
            id: Some(src.id),
            name: src.name.clone().into(),
            nmx_m_id: src.nmx_m_id,
            domain_uuid: Some(src.domain_uuid),
            logical_partition_id: src.logical_partition_id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NvlPartitionSnapshotPgJson {
    pub id: NvLinkPartitionId,
    pub nmx_m_id: String,
    pub name: NvlPartitionName,
    pub domain_uuid: NvLinkDomainId,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
}

impl TryFrom<NvlPartitionSnapshotPgJson> for NvlPartition {
    type Error = sqlx::Error;
    fn try_from(value: NvlPartitionSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            nmx_m_id: value.nmx_m_id,
            domain_uuid: value.domain_uuid,
            name: value.name,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
            logical_partition_id: value.logical_partition_id,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for NvlPartitionSnapshotPgJson {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        NvlPartitionSnapshotPgJson::deserialize(json).map_err(|err| sqlx::Error::Decode(err.into()))
    }
}

impl<'r> FromRow<'r, PgRow> for NvlPartition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        NvlPartitionSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}
