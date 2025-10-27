/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use super::typed_uuids::{TypedUuid, UuidSubtype};
use crate::{UuidConversionError, grpc_uuid_message};

/// VpcId is a strongly typed UUID specific to a VPC ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct VpcId(pub uuid::Uuid);

grpc_uuid_message!(VpcId);

impl From<VpcId> for uuid::Uuid {
    fn from(id: VpcId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for VpcId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for VpcId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "VpcId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for VpcId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for VpcId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

pub struct VpcPrefixMarker {}

impl UuidSubtype for VpcPrefixMarker {
    const TYPE_NAME: &'static str = "VpcPrefixId";
}

pub type VpcPrefixId = TypedUuid<VpcPrefixMarker>;
