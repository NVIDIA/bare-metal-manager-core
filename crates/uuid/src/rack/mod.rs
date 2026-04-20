/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use prost::DecodeError;
use prost::bytes::{Buf, BufMut};
use prost::encoding::{DecodeContext, WireType};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlx")]
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgHasArrayType, PgTypeInfo},
    {Database, Postgres, Row},
};

use crate::DbPrimaryUuid;

/// The `RackId` uniquely identifies a rack that is managed by the system.
///
/// `RackId` is a newtype over `String`. The value is typically provided by
/// an external Datacenter Inventory Manager (DCIM) and can be in any format
/// that the DCIM uses (e.g. "P20", "rack-42-us-west", or the legacy
/// `ps100...` encoded format).
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RackId(String);

impl RackId {
    /// Creates a new RackId from any string value.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RackId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for RackId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RackId {
    type Err = RackIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(RackIdParseError::Empty);
        }
        Ok(Self(s.to_string()))
    }
}

impl From<&str> for RackId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RackId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for RackId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl DbPrimaryUuid for RackId {
    fn db_primary_uuid_name() -> &'static str {
        "rack_id"
    }
}

// Make RackId bindable directly into a sqlx query.
#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for RackId {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        buf.extend(self.0.as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

#[cfg(feature = "sqlx")]
impl<'r, DB> sqlx::Decode<'r, DB> for RackId
where
    DB: sqlx::database::Database,
    String: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::database::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let str_id: String = String::decode(value)?;
        Ok(RackId(str_id))
    }
}

#[cfg(feature = "sqlx")]
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for RackId {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let id: RackId = row.try_get::<RackId, _>(0)?;
        Ok(id)
    }
}

#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for RackId
where
    DB: sqlx::Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        String::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        String::compatible(ty)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for RackId {
    fn array_type_info() -> PgTypeInfo {
        <&str as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <&str as PgHasArrayType>::array_compatible(ty)
    }
}

// Implement [`prost::Message`] manually so that we can be wire-compatible with the
// `.common.RackId` protobuf message, which is defined as:
//
// ```protobuf
// message RackId {
//     string id = 1;
// }
// ```
impl prost::Message for RackId {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        legacy_rpc::RackId::from(self.clone()).encode_raw(buf);
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        Self: Sized,
    {
        let mut legacy_message = legacy_rpc::RackId::from(self.clone());
        legacy_message.merge_field(tag, wire_type, buf, ctx)?;
        self.0 = legacy_message.id;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        legacy_rpc::RackId::from(self.clone()).encoded_len()
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

mod legacy_rpc {
    /// Backwards compatibility shim for [`super::RackId`] to be sent as a protobuf message
    /// in a way that is compatible with the `.common.RackId` message, which is defined as:
    ///
    /// ```ignore
    /// message RackId {
    ///     string id = 1;
    /// }
    /// ```
    #[derive(prost::Message)]
    pub struct RackId {
        #[prost(string, tag = "1")]
        pub id: String,
    }

    impl From<super::RackId> for RackId {
        fn from(value: super::RackId) -> Self {
            Self { id: value.0 }
        }
    }
}

/// The `RackProfileId` identifies which rack profile (hardware identity
/// and expected device capabilities) applies to a rack.
///
/// `RackProfileId` is a newtype over `String`. Values are defined as keys
/// in the `[rack_profiles.<id>]` configuration section (e.g. "NVL72",
/// "NVL36").
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RackProfileId(String);

impl RackProfileId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RackProfileId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for RackProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RackProfileId {
    type Err = RackIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(RackIdParseError::Empty);
        }
        Ok(Self(s.to_string()))
    }
}

impl From<&str> for RackProfileId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RackProfileId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for RackProfileId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for RackProfileId {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        buf.extend(self.0.as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

#[cfg(feature = "sqlx")]
impl<'r, DB> sqlx::Decode<'r, DB> for RackProfileId
where
    DB: sqlx::database::Database,
    String: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::database::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let str_id: String = String::decode(value)?;
        Ok(RackProfileId(str_id))
    }
}

#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for RackProfileId
where
    DB: sqlx::Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        String::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        String::compatible(ty)
    }
}

#[cfg(feature = "sqlx")]
impl PgHasArrayType for RackProfileId {
    fn array_type_info() -> PgTypeInfo {
        <&str as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <&str as PgHasArrayType>::array_compatible(ty)
    }
}

impl prost::Message for RackProfileId {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        rack_profile_id_rpc::RackProfileId::from(self.clone()).encode_raw(buf);
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        Self: Sized,
    {
        let mut msg = rack_profile_id_rpc::RackProfileId::from(self.clone());
        msg.merge_field(tag, wire_type, buf, ctx)?;
        self.0 = msg.id;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        rack_profile_id_rpc::RackProfileId::from(self.clone()).encoded_len()
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

mod rack_profile_id_rpc {
    #[derive(prost::Message)]
    pub struct RackProfileId {
        #[prost(string, tag = "1")]
        pub id: String,
    }

    impl From<super::RackProfileId> for RackProfileId {
        fn from(value: super::RackProfileId) -> Self {
            Self { id: value.0 }
        }
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum RackIdParseError {
    #[error("RackId cannot be empty")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rack_id_round_trip_legacy() {
        // Legacy ps100-encoded rack IDs should still work.
        let rack_id_str = "ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
        let rack_id = RackId::from_str(rack_id_str)
            .expect("Should have successfully converted from a valid string");
        let round_tripped = rack_id.to_string();
        assert_eq!(rack_id_str, round_tripped);
    }

    #[test]
    fn test_rack_id_arbitrary_string() {
        // DCIM-provided rack IDs can be any non-empty string.
        let rack_id = RackId::from_str("P20").unwrap();
        assert_eq!(rack_id.to_string(), "P20");

        let rack_id = RackId::from_str("rack-42-us-west-2").unwrap();
        assert_eq!(rack_id.to_string(), "rack-42-us-west-2");

        let rack_id = RackId::from_str("i-am-just-a-rack-id").unwrap();
        assert_eq!(rack_id.to_string(), "i-am-just-a-rack-id");
    }

    #[test]
    fn test_rack_id_empty_fails() {
        assert!(RackId::from_str("").is_err());
    }

    #[test]
    fn test_rack_id_serde_round_trip() {
        let rack_id = RackId::new("my-custom-rack");
        let json = serde_json::to_string(&rack_id).unwrap();
        assert_eq!(json, "\"my-custom-rack\"");
        let deserialized: RackId = serde_json::from_str(&json).unwrap();
        assert_eq!(rack_id, deserialized);
    }

    #[test]
    fn test_rack_id_from_str_impls() {
        let rack_id: RackId = "test-rack".into();
        assert_eq!(rack_id.as_str(), "test-rack");

        let rack_id = RackId::from("another-rack");
        assert_eq!(rack_id.as_str(), "another-rack");

        let rack_id = RackId::from(String::from("string-rack"));
        assert_eq!(rack_id.as_str(), "string-rack");
    }
}
