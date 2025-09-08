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

/// NetworkSegmentId is a strongly typed UUID specific to a network
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc. This
/// is similar to what we do for MachineId, VpcId, InstanceId, and
/// basically all of the IDs in measured boot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct NetworkSegmentId(pub uuid::Uuid);

impl From<NetworkSegmentId> for uuid::Uuid {
    fn from(id: NetworkSegmentId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NetworkSegmentId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for NetworkSegmentId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("NetworkSegmentId", input.to_string())
        })?))
    }
}

impl fmt::Display for NetworkSegmentId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<NetworkSegmentId> for crate::common::Uuid {
    fn from(val: NetworkSegmentId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<crate::common::Uuid> for NetworkSegmentId {
    type Error = RpcDataConversionError;
    fn try_from(msg: crate::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<&crate::common::Uuid> for NetworkSegmentId {
    type Error = RpcDataConversionError;
    fn try_from(msg: &crate::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<crate::common::Uuid>> for NetworkSegmentId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<crate::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            // TODO(chet): Maybe this isn't the right place for this, since
            // depending on the proto message, the field name can differ (which
            // should actually probably be standardized anyway), or we can just
            // take a similar approach to ::InvalidUuid can say "field of type"?
            return Err(eyre::eyre!("missing segment_id argument").into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl NetworkSegmentId {
    pub fn from_grpc(msg: Option<crate::common::Uuid>) -> Result<Self, Box<Status>> {
        Self::try_from(msg).map_err(|e| {
            Box::new(Status::invalid_argument(format!(
                "bad grpc network segment ID: {e}"
            )))
        })
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for NetworkSegmentId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}
