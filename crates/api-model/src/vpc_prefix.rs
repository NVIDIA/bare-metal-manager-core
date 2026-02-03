use std::collections::HashMap;

/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use rpc::errors::RpcDataConversionError;
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

impl TryFrom<rpc::forge::VpcPrefixCreationRequest> for NewVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcPrefixCreationRequest) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixCreationRequest {
            id,
            prefix,
            name,
            vpc_id,
            config,
            metadata,
        } = value;

        let id = id.unwrap_or_else(VpcPrefixId::new);
        let vpc_id = vpc_id.ok_or(RpcDataConversionError::MissingArgument("vpc_id"))?;
        // let id = VpcPrefixId::new();

        Ok(Self {
            id,
            config: match config {
                Some(c) => VpcPrefixConfig::try_from(c)?,
                // Deprecated fields support
                None => VpcPrefixConfig {
                    prefix: IpNetwork::try_from(prefix.as_str())?,
                },
            },
            metadata: match metadata {
                Some(m) => Metadata::try_from(m)?,
                // Deprecated fields support
                None => Metadata {
                    name,
                    ..Default::default()
                },
            },
            vpc_id,
        })
    }
}

impl TryFrom<rpc::forge::VpcPrefixConfig> for VpcPrefixConfig {
    type Error = RpcDataConversionError;

    fn try_from(rpc_config: rpc::forge::VpcPrefixConfig) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixConfig { prefix } = rpc_config;

        Ok(Self {
            prefix: IpNetwork::try_from(prefix.as_str())?,
        })
    }
}

impl TryFrom<rpc::forge::VpcPrefixUpdateRequest> for UpdateVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(
        rpc_update_prefix: rpc::forge::VpcPrefixUpdateRequest,
    ) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixUpdateRequest {
            id,
            prefix,
            name,
            config,
            metadata,
        } = rpc_update_prefix;

        if prefix.is_some()
            || config
                .as_ref()
                .map(|c| !c.prefix.is_empty())
                .unwrap_or(false)
        {
            return Err(RpcDataConversionError::InvalidArgument(
                "Resizing VPC prefixes is currently unsupported".to_owned(),
            ));
        }

        let id = id.ok_or(RpcDataConversionError::MissingArgument("id"))?;

        // At least one update field must be set
        if metadata.is_none() && name.is_none() {
            return Err(RpcDataConversionError::InvalidArgument(
                "At least one updated field must be set".to_owned(),
            ));
        }

        let metadata = match metadata {
            Some(m) => Metadata::try_from(m)?,
            // Deprecated field handling
            None => Metadata {
                name: name.unwrap_or_default(),
                ..Default::default()
            },
        };

        Ok(Self { id, metadata })
    }
}

impl TryFrom<rpc::forge::VpcPrefixDeletionRequest> for DeleteVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(
        rpc_delete_prefix: rpc::forge::VpcPrefixDeletionRequest,
    ) -> Result<Self, Self::Error> {
        let id = rpc_delete_prefix
            .id
            .ok_or(RpcDataConversionError::MissingArgument("id"))?;
        Ok(Self { id })
    }
}

impl From<VpcPrefixStatus> for rpc::forge::VpcPrefixStatus {
    fn from(db_status: VpcPrefixStatus) -> Self {
        let VpcPrefixStatus {
            total_31_segments,
            available_31_segments,
            ..
        } = db_status;

        Self {
            total_31_segments,
            available_31_segments,
        }
    }
}

impl From<VpcPrefix> for rpc::forge::VpcPrefix {
    fn from(db_vpc_prefix: VpcPrefix) -> Self {
        let VpcPrefix {
            id,
            config,
            metadata,
            status,
            vpc_id,
            ..
        } = db_vpc_prefix;

        let id = Some(id);
        let prefix = config.prefix.to_string();
        let vpc_id = Some(vpc_id);

        Self {
            id,
            prefix: prefix.clone(),      // Deprecated
            name: metadata.name.clone(), // Deprecated
            vpc_id,
            total_31_segments: status.total_31_segments, // Deprecated
            available_31_segments: status.available_31_segments, // Deprecated
            status: Some(status.into()),
            metadata: Some(metadata.into()),
            config: Some(rpc::forge::VpcPrefixConfig { prefix }),
        }
    }
}
