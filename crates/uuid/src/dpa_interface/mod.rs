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
use sqlx::postgres::{PgHasArrayType, PgTypeInfo};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, Type};

use crate::{UuidConversionError, grpc_uuid_message};

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default, Ord, PartialOrd,
)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct DpaInterfaceId(pub uuid::Uuid);

grpc_uuid_message!(DpaInterfaceId);

pub const NULL_DPA_INTERFACE_ID: DpaInterfaceId = DpaInterfaceId(uuid::Uuid::nil());

impl From<DpaInterfaceId> for uuid::Uuid {
    fn from(id: DpaInterfaceId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for DpaInterfaceId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for DpaInterfaceId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "DpaInterfaceId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for DpaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for DpaInterfaceId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
