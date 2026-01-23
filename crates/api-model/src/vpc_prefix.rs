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
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use rpc::errors::RpcDataConversionError;
use sqlx::Row;
use sqlx::postgres::PgRow;

#[derive(Clone, Debug)]
pub struct VpcPrefix {
    pub id: VpcPrefixId,
    pub prefix: IpNetwork,
    pub name: String,
    pub vpc_id: VpcId,
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
        Ok(VpcPrefix {
            id,
            prefix,
            name,
            vpc_id,
            last_used_prefix,
            total_31_segments: 0,
            available_31_segments: 0,
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
    pub prefix: IpNetwork,
    pub name: String,
    pub vpc_id: VpcId,
}

pub struct UpdateVpcPrefix {
    pub id: VpcPrefixId,
    // This is all we support updating at the moment. In the future we might
    // also implement prefix resizing, and at that point we'll need to use
    // Option for all the fields.
    pub name: String,
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
        } = value;

        let id = id.unwrap_or_else(|| VpcPrefixId::from(uuid::Uuid::new_v4()));
        let vpc_id = vpc_id.ok_or(RpcDataConversionError::MissingArgument("vpc_id"))?;
        let prefix = IpNetwork::try_from(prefix.as_str())?;
        // let id = VpcPrefixId::from(uuid::Uuid::new_v4());

        Ok(Self {
            id,
            prefix,
            name,
            vpc_id,
        })
    }
}

impl TryFrom<rpc::forge::VpcPrefixUpdateRequest> for UpdateVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(
        rpc_update_prefix: rpc::forge::VpcPrefixUpdateRequest,
    ) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixUpdateRequest { id, prefix, name } = rpc_update_prefix;

        prefix
            .map(|_| -> Result<(), RpcDataConversionError> {
                Err(RpcDataConversionError::InvalidArgument(
                    "Resizing VPC prefixes is currently unsupported".to_owned(),
                ))
            })
            .transpose()?;
        let id = id.ok_or(RpcDataConversionError::MissingArgument("id"))?;
        let name = name.ok_or_else(|| {
            RpcDataConversionError::InvalidArgument(
                "At least one updated field must be set".to_owned(),
            )
        })?;

        Ok(Self { id, name })
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

impl From<VpcPrefix> for rpc::forge::VpcPrefix {
    fn from(db_vpc_prefix: VpcPrefix) -> Self {
        let VpcPrefix {
            id,
            prefix,
            name,
            vpc_id,
            ..
        } = db_vpc_prefix;

        let id = Some(id);
        let prefix = prefix.to_string();
        let vpc_id = Some(vpc_id);

        Self {
            id,
            prefix,
            name,
            vpc_id,
            total_31_segments: db_vpc_prefix.total_31_segments,
            available_31_segments: db_vpc_prefix.available_31_segments,
        }
    }
}
