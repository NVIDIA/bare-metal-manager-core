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

use carbide_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use model::metadata::Metadata;
use model::vpc_prefix::{
    DeleteVpcPrefix, NewVpcPrefix, UpdateVpcPrefix, VpcPrefix, VpcPrefixConfig, VpcPrefixStatus,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl TryFrom<rpc::forge::VpcPrefixCreationRequest> for NewVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcPrefixCreationRequest) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixCreationRequest {
            id,
            prefix,
            vpc_id,
            config,
            metadata,
        } = value;

        let id = id.unwrap_or_else(VpcPrefixId::new);
        let vpc_id = vpc_id.ok_or(RpcDataConversionError::MissingArgument("vpc_id"))?;

        let metadata = match metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!(
                "VPCPrefix metadata is not valid: {}",
                e
            ))
        })?;

        let config = match config {
            Some(config) => VpcPrefixConfig::try_from(config)?,
            None => VpcPrefixConfig {
                prefix: IpNetwork::try_from(prefix.as_str())?,
            },
        };

        Ok(Self {
            id,
            config,
            metadata,
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

        let metadata = match metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!(
                "VPC prefix metadata is not valid: {}",
                e
            ))
        })?;

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
            total_linknet_segments,
            available_linknet_segments,
            ..
        } = db_status;

        Self {
            total_31_segments,
            available_31_segments,
            total_linknet_segments,
            available_linknet_segments,
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
            prefix: prefix.clone(), // Deprecated
            vpc_id,
            total_31_segments: status.total_31_segments, // Deprecated
            available_31_segments: status.available_31_segments, // Deprecated
            status: Some(status.into()),
            metadata: Some(metadata.into()),
            config: Some(rpc::forge::VpcPrefixConfig { prefix }),
        }
    }
}
