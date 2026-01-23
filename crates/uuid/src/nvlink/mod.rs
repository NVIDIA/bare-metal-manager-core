/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::{PgHasArrayType, PgTypeInfo},
    {FromRow, Type},
};

use crate::{UuidConversionError, grpc_uuid_message};

/// NvlinkPartitionId is a strongly typed UUID specific to an Infiniband
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc. This
/// is similar to what we do for MachineId, VpcId, InstanceId,
/// NetworkSegmentId, and basically all of the IDs in measured boot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct NvLinkPartitionId(pub uuid::Uuid);

grpc_uuid_message!(NvLinkPartitionId);

impl From<NvLinkPartitionId> for uuid::Uuid {
    fn from(id: NvLinkPartitionId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NvLinkPartitionId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for NvLinkPartitionId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "NvlinkPartitionId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for NvLinkPartitionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for NvLinkPartitionId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct NvLinkLogicalPartitionId(pub uuid::Uuid);

grpc_uuid_message!(NvLinkLogicalPartitionId);

impl From<NvLinkLogicalPartitionId> for uuid::Uuid {
    fn from(id: NvLinkLogicalPartitionId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NvLinkLogicalPartitionId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for NvLinkLogicalPartitionId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "NvlinkLogicalPartitionId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for NvLinkLogicalPartitionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for NvLinkLogicalPartitionId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct NvLinkDomainId(pub uuid::Uuid);

grpc_uuid_message!(NvLinkDomainId);

impl From<NvLinkDomainId> for uuid::Uuid {
    fn from(id: NvLinkDomainId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NvLinkDomainId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for NvLinkDomainId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "NvlinkinkDomainId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for NvLinkDomainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for NvLinkDomainId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
