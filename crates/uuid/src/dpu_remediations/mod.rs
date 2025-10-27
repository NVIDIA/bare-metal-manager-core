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

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    postgres::{PgHasArrayType, PgTypeInfo},
    {FromRow, Type},
};

use crate::typed_uuids::{TypedUuid, UuidSubtype};
use crate::{UuidConversionError, grpc_uuid_message};

/// RemediationId is a strongly typed UUID specific to a Remediation ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "sqlx", derive(FromRow, Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "UUID"))]
pub struct RemediationId(pub uuid::Uuid);

grpc_uuid_message!(RemediationId);

impl From<RemediationId> for uuid::Uuid {
    fn from(id: RemediationId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for RemediationId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}
impl FromStr for RemediationId {
    type Err = UuidConversionError;
    fn from_str(input: &str) -> Result<Self, UuidConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            UuidConversionError::InvalidUuid {
                ty: "RemediationId",
                value: input.to_string(),
            }
        })?))
    }
}

impl fmt::Display for RemediationId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RemediationId> for Option<uuid::Uuid> {
    fn from(val: RemediationId) -> Self {
        Some(val.into())
    }
}

impl TryFrom<Option<uuid::Uuid>> for RemediationId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<uuid::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(eyre::eyre!("missing remediation_id argument").into());
        };
        Ok(Self::from(input_uuid))
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for RemediationId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

pub struct RemediationPrefixMarker {}

impl UuidSubtype for RemediationPrefixMarker {
    const TYPE_NAME: &'static str = "RemediationPrefixId";
}

pub type RemediationPrefixId = TypedUuid<RemediationPrefixMarker>;
