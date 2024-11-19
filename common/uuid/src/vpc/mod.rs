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

use ::rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::{PgHasArrayType, PgTypeInfo},
    {FromRow, Type},
};

/// VpcId is a strongly typed UUID specific to a VPC ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct VpcId(pub uuid::Uuid);

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
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("VpcId", input.to_string())
        })?))
    }
}

impl fmt::Display for VpcId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<VpcId> for ::rpc::common::Uuid {
    fn from(val: VpcId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<::rpc::common::Uuid> for VpcId {
    type Error = RpcDataConversionError;
    fn try_from(msg: ::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<::rpc::common::Uuid>> for VpcId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<::rpc::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(eyre::eyre!("missing vpc_id argument").into());
        };
        Ok(Self::try_from(input_uuid)?)
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
