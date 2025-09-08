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

use std::{fmt, str::FromStr};

use crate::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{FromRow, Type};

#[cfg(feature = "sqlx")]
use sqlx::postgres::{PgHasArrayType, PgTypeInfo};
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct DpaInterfaceId(pub uuid::Uuid);

pub const NULL_DPA_INTERFACE_ID: DpaInterfaceId = DpaInterfaceId(uuid::Uuid::nil());

impl From<DpaInterfaceId> for uuid::Uuid {
    fn from(id: DpaInterfaceId) -> Self {
        id.0
    }
}

impl From<DpaInterfaceId> for crate::common::Uuid {
    fn from(id: DpaInterfaceId) -> Self {
        crate::common::Uuid {
            value: id.0.to_string(),
        }
    }
}

impl From<uuid::Uuid> for DpaInterfaceId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for DpaInterfaceId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("DpaInterfaceId", input.to_string())
        })?))
    }
}

impl TryFrom<&crate::common::Uuid> for DpaInterfaceId {
    type Error = RpcDataConversionError;
    fn try_from(msg: &crate::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
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
