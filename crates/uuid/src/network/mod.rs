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
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::{PgHasArrayType, PgTypeInfo},
    {FromRow, Type},
};

use crate::{UuidConversionError, grpc_uuid_message};

/// NetworkSegmentId is a strongly typed UUID specific to a network
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc. This
/// is similar to what we do for MachineId, VpcId, InstanceId, and
/// basically all of the IDs in measured boot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, Hash, PartialEq, Default)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct NetworkSegmentId(pub uuid::Uuid);

grpc_uuid_message!(NetworkSegmentId);

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
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "NetworkSegmentId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for NetworkSegmentId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
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

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialOrd, Ord, Eq, PartialEq, Hash, Default,
)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
#[repr(transparent)]
pub struct NetworkPrefixId(pub uuid::Uuid);

grpc_uuid_message!(NetworkPrefixId);

impl Display for NetworkPrefixId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NetworkPrefixId> for uuid::Uuid {
    fn from(id: NetworkPrefixId) -> Self {
        id.0
    }
}

impl From<&NetworkPrefixId> for uuid::Uuid {
    fn from(id: &NetworkPrefixId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NetworkPrefixId {
    fn from(value: uuid::Uuid) -> Self {
        NetworkPrefixId(value)
    }
}

impl From<&uuid::Uuid> for NetworkPrefixId {
    fn from(value: &uuid::Uuid) -> Self {
        NetworkPrefixId(*value)
    }
}

impl FromStr for NetworkPrefixId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "NetworkSegmentId",
                value: input.to_string(),
            }
        })?))
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for NetworkPrefixId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

#[test]
fn test_network_prefix_id_serialization() {
    // Make sure NetworkPrefixId serializes as a simple UUID.
    let id = uuid::Uuid::new_v4();
    let network_prefix_id = NetworkPrefixId::from(id);

    let uuid_json = serde_json::to_string(&id).unwrap();
    let nsid_json = serde_json::to_string(&network_prefix_id).unwrap();

    assert_eq!(uuid_json, nsid_json);
}
