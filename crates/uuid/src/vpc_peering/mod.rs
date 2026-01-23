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
    FromRow, Type,
    postgres::{PgHasArrayType, PgTypeInfo},
};

use crate::{UuidConversionError, grpc_uuid_message};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct VpcPeeringId(pub uuid::Uuid);

grpc_uuid_message!(VpcPeeringId);

impl From<VpcPeeringId> for uuid::Uuid {
    fn from(id: VpcPeeringId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for VpcPeeringId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for VpcPeeringId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "VpcPeeringId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for VpcPeeringId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for VpcPeeringId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
