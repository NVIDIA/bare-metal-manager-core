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

use crate::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use tonic::Status;

#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::{PgHasArrayType, PgTypeInfo},
    {FromRow, Type},
};

/// InstanceId is a strongly typed UUID specific to an instance ID,
/// with trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc. This is similar
/// to what we do for MachineId, VpcId, and basically all of the IDs
/// in measured boot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct InstanceId(pub uuid::Uuid);

impl From<InstanceId> for uuid::Uuid {
    fn from(id: InstanceId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for InstanceId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for InstanceId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("InstanceId", input.to_string())
        })?))
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<InstanceId> for crate::common::Uuid {
    fn from(val: InstanceId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl From<InstanceId> for Option<crate::common::Uuid> {
    fn from(val: InstanceId) -> Self {
        Some(crate::common::Uuid {
            value: val.to_string(),
        })
    }
}

impl From<&InstanceId> for crate::common::Uuid {
    fn from(val: &InstanceId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl From<&InstanceId> for Option<crate::common::Uuid> {
    fn from(val: &InstanceId) -> Self {
        Some(crate::common::Uuid {
            value: val.to_string(),
        })
    }
}

impl TryFrom<crate::common::Uuid> for InstanceId {
    type Error = RpcDataConversionError;
    fn try_from(msg: crate::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<crate::common::Uuid>> for InstanceId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<crate::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            // TODO(chet): Maybe this isn't the right place for this, since
            // depending on the proto message, the field name can differ (which
            // should actually probably be standardized anyway), or we can just
            // take a similar approach to ::InvalidUuid can say "field of type"?
            return Err(eyre::eyre!("missing vpc_id argument").into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl InstanceId {
    pub fn from_grpc(msg: Option<crate::common::Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad grpc instance ID: {e}")))
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for InstanceId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
