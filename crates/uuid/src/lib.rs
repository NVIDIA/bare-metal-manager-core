/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::error::Error;
use std::fmt;

pub mod domain;
pub mod dpa_interface;
pub mod dpu_remediations;
pub mod extension_service;
pub mod infiniband;
pub mod instance;
pub mod instance_type;
pub mod machine;
pub mod measured_boot;
pub mod network;
pub mod network_security_group;
pub mod nvlink;
pub mod power_shelf;
pub mod rack;
pub mod switch;
pub mod typed_uuids;
pub mod vpc;
pub mod vpc_peering;
#[derive(Debug)]
pub struct UuidEmptyStringError;

impl fmt::Display for UuidEmptyStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "input UUID string cannot be empty",)
    }
}

impl Error for UuidEmptyStringError {}

/// DbPrimaryUuid is a trait intended for primary keys which
/// derive the sqlx UUID type. The intent is the db_primary_uuid_name
/// function should return the name of the column for the primary
/// UUID-typed key, which allows dynamic compositon of a SQL query.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbPrimaryUuid {
    fn db_primary_uuid_name() -> &'static str;
}

/// DbTable is a trait intended for table records which derive
/// sqlx FromRow. The intent here is db_table_name() will return
/// the actual name of the table the records are in, allowing for
/// dynamic composition of an SQL query for that table.
///
/// This was originally introduced as part of the measured boot
/// generics (and lived in src/measured_boot/), but moved here.
pub trait DbTable {
    fn db_table_name() -> &'static str;
}

#[derive(thiserror::Error, Debug)]
pub enum UuidConversionError {
    #[error("Invalid UUID for {ty}: {value}")]
    InvalidUuid { ty: &'static str, value: String },
    #[error("Missing ID for {0}")]
    MissingId(&'static str),
    #[error("Invalid MachineId: {0}")]
    InvalidMachineId(String),
}

#[derive(
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    Clone,
    PartialEq,
    Eq,
    Hash,
    ::prost::Message,
)]
pub(crate) struct CommonUuidPlaceholder {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}

/// Implements `prost::Message` for a Uuid wrapper that is wire-compatible
/// with common.UUID (`{ string value = 1; }`).
///
/// Usage:
///     grpc_uuid_message!(uuid::machine::DomainId);
#[macro_export]
macro_rules! grpc_uuid_message {
    ($ty:ty) => {
        impl ::prost::Message for $ty {
            fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
                let tmp = $crate::CommonUuidPlaceholder {
                    value: self.0.to_string(),
                };
                // Delegate to prost for the actual encoding of the shim.
                ::prost::Message::encode_raw(&tmp, buf);
            }

            fn merge_field(
                &mut self,
                tag: u32,
                wire_type: ::prost::encoding::WireType,
                buf: &mut impl ::prost::bytes::Buf,
                ctx: ::prost::encoding::DecodeContext,
            ) -> Result<(), ::prost::DecodeError> {
                // Decode through the shim type, which has the identical wire layout.
                let mut tmp = <$crate::CommonUuidPlaceholder>::default();
                ::prost::Message::merge_field(&mut tmp, tag, wire_type, buf, ctx)?;
                let parsed = ::uuid::Uuid::parse_str(&tmp.value).map_err(|_| {
                    ::prost::DecodeError::new(format!("invalid UUID: {}", tmp.value))
                })?;
                *self = Self(parsed);
                Ok(())
            }

            fn encoded_len(&self) -> usize {
                let tmp = $crate::CommonUuidPlaceholder {
                    value: self.0.to_string(),
                };
                ::prost::Message::encoded_len(&tmp)
            }

            fn clear(&mut self) {
                *self = Self::default();
            }
        }
    };
}
