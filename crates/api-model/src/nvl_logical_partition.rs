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

use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use rpc::errors::RpcDataConversionError;
use rpc::forge as rpc_forge;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;
use crate::tenant::TenantOrganizationId;

#[derive(Clone, Debug, Default)]
pub struct NvLinkLogicalPartitionSearchFilter {
    pub name: Option<String>,
}

impl From<rpc_forge::NvLinkLogicalPartitionSearchFilter> for NvLinkLogicalPartitionSearchFilter {
    fn from(filter: rpc_forge::NvLinkLogicalPartitionSearchFilter) -> Self {
        NvLinkLogicalPartitionSearchFilter { name: filter.name }
    }
}

#[derive(Debug, Clone)]
pub struct NewLogicalPartition {
    pub id: NvLinkLogicalPartitionId,
    pub config: LogicalPartitionConfig,
}

impl TryFrom<rpc_forge::NvLinkLogicalPartitionCreationRequest> for NewLogicalPartition {
    type Error = RpcDataConversionError;
    fn try_from(
        value: rpc_forge::NvLinkLogicalPartitionCreationRequest,
    ) -> Result<Self, Self::Error> {
        let id: NvLinkLogicalPartitionId = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let conf = value.config.ok_or_else(|| {
            RpcDataConversionError::InvalidArgument(
                "NvLinkLogicalPartition config is empty".to_string(),
            )
        })?;

        Ok(NewLogicalPartition {
            id,
            config: LogicalPartitionConfig::try_from(conf)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LogicalPartitionConfig {
    pub metadata: Metadata,
    pub tenant_organization_id: TenantOrganizationId,
}

impl TryFrom<rpc_forge::NvLinkLogicalPartitionConfig> for LogicalPartitionConfig {
    type Error = RpcDataConversionError;

    fn try_from(conf: rpc_forge::NvLinkLogicalPartitionConfig) -> Result<Self, Self::Error> {
        if conf.tenant_organization_id.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "NvLinkLogicalPartition organization_id is empty".to_string(),
            ));
        }

        let tenant_organization_id =
            TenantOrganizationId::try_from(conf.tenant_organization_id.clone()).map_err(|_| {
                RpcDataConversionError::InvalidArgument(conf.tenant_organization_id)
            })?;

        Ok(LogicalPartitionConfig {
            metadata: conf.metadata.unwrap_or_default().try_into()?,
            tenant_organization_id,
        })
    }
}

impl TryFrom<LogicalPartitionConfig> for rpc_forge::NvLinkLogicalPartitionConfig {
    type Error = RpcDataConversionError;
    fn try_from(src: LogicalPartitionConfig) -> Result<Self, Self::Error> {
        Ok(rpc_forge::NvLinkLogicalPartitionConfig {
            metadata: Some(src.metadata.into()),
            tenant_organization_id: src.tenant_organization_id.to_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LogicalPartitionName(String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum LogicalPartitionState {
    Provisioning,
    Ready,
    Updating,
    Error,
    Deleting,
}

#[derive(Debug, Clone)]
pub struct LogicalPartition {
    pub id: NvLinkLogicalPartitionId,

    pub name: String,
    pub description: String,
    pub tenant_organization_id: TenantOrganizationId,

    pub config_version: ConfigVersion,

    pub partition_state: LogicalPartitionState,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

/// Returns whether a logical partition was deleted by user
pub fn is_marked_as_deleted(partition: &LogicalPartition) -> bool {
    partition.deleted.is_some()
}

impl TryFrom<LogicalPartition> for rpc_forge::NvLinkLogicalPartition {
    type Error = RpcDataConversionError;
    fn try_from(src: LogicalPartition) -> Result<Self, Self::Error> {
        let mut state = match &src.partition_state {
            LogicalPartitionState::Provisioning => rpc_forge::TenantState::Provisioning,
            LogicalPartitionState::Ready => rpc_forge::TenantState::Ready,
            LogicalPartitionState::Error => rpc_forge::TenantState::Failed,
            LogicalPartitionState::Deleting => rpc_forge::TenantState::Terminating,
            LogicalPartitionState::Updating => rpc_forge::TenantState::Updating,
        };

        if is_marked_as_deleted(&src) {
            state = rpc_forge::TenantState::Terminating;
        }
        let status = Some(rpc_forge::NvLinkLogicalPartitionStatus {
            state: state as i32,
        });

        let config = rpc_forge::NvLinkLogicalPartitionConfig {
            metadata: Some(rpc::Metadata {
                name: src.name,
                description: src.description,
                ..Default::default()
            }),
            tenant_organization_id: src.tenant_organization_id.to_string(),
        };

        Ok(rpc_forge::NvLinkLogicalPartition {
            id: Some(src.id),
            config_version: src.config_version.version_string(),
            status,
            config: Some(config),
            created: Some(src.created.into()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogicalPartitionSnapshotPgJson {
    pub id: NvLinkLogicalPartitionId,
    pub name: String,
    pub description: String,
    pub tenant_organization_id: TenantOrganizationId,
    pub config_version: ConfigVersion,
    pub partition_state: LogicalPartitionState,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

impl TryFrom<LogicalPartitionSnapshotPgJson> for LogicalPartition {
    type Error = sqlx::Error;
    fn try_from(value: LogicalPartitionSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            name: value.name,
            description: value.description,
            tenant_organization_id: value.tenant_organization_id,
            config_version: value.config_version,
            partition_state: value.partition_state,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for LogicalPartitionSnapshotPgJson {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        LogicalPartitionSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))
    }
}
