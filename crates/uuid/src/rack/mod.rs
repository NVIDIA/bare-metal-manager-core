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
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Debug, Display, Formatter, Write};
use std::str::FromStr;

use data_encoding::BASE32_DNSSEC;
use prost::DecodeError;
use prost::bytes::{Buf, BufMut};
use prost::encoding::{DecodeContext, WireType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "sqlx")]
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgHasArrayType, PgTypeInfo},
    {Database, Postgres, Row},
};

use crate::DbPrimaryUuid;

/// This is a fixed-size hash of the rack hardware.
pub type HardwareHash = [u8; 32];
/// This is the base32-encoded representation of the hardware hash. It is a fixed size instead of a
/// String so that we can implement the Copy trait.
pub type HardwareIdBase32 = [u8; RACK_ID_HARDWARE_ID_BASE32_LENGTH];

/// The `RackId` uniquely identifies a rack that is managed by the Forge system
///
/// `RackId`s are derived from a hardware fingerprint, and are thereby
/// globally unique.
///
/// RackIds are using an encoding which makes them valid DNS names.
/// This requires the use of lowercase characters only.
///
/// Examples for RackIds can be:
/// - ps100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
/// - ps100rtjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
/// - ps100hsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g
/// - ps100rsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g
/// - ps100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct RackId {
    /// The hardware source from which the Rack ID was derived
    source: RackIdSource,
    /// The rack hash which was derived via hashing from the hardware piece
    /// that is indicated in `source`, encoded via base32. Must be valid utf-8.
    hardware_id: HardwareIdBase32,
    /// The Type of the Rack
    ty: RackType,
}

impl Ord for RackId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for RackId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for RackId {
    #[allow(deprecated)]
    fn default() -> Self {
        Self::default()
    }
}

impl Debug for RackId {
    // The derived Debug implementation is messy, just output the string
    // representation even when debugging.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

// Make RackId bindable directly into a sqlx query.
#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for RackId {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        buf.extend(self.to_string().as_bytes());
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
        Ok(RackId::from_str(&str_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?)
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

impl RackId {
    pub fn new(source: RackIdSource, hardware_hash: HardwareHash, ty: RackType) -> RackId {
        // BASE32_DNSSEC is chosen to just generate lowercase characters and
        // numbers - which will result in valid DNS names for RackIds.
        let encoded = BASE32_DNSSEC.encode(&hardware_hash);
        assert_eq!(encoded.len(), RACK_ID_HARDWARE_ID_BASE32_LENGTH);

        Self {
            source,
            hardware_id: encoded.as_bytes().try_into().unwrap(),
            ty,
        }
    }

    /// The hardware source from which the Rack ID was derived
    pub fn source(&self) -> RackIdSource {
        self.source
    }

    /// The type of the Rack
    pub fn rack_type(&self) -> RackType {
        self.ty
    }

    /// Generate Remote ID based on Rack ID.
    /// Remote Id is inserted by dhcrelay on DPU in each DHCP request sent by host.
    /// This field is used only for DPU.
    pub fn remote_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_string().as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        BASE32_DNSSEC.encode(&hash)
    }

    /// NOTE: NEVER USE THIS!
    /// Tonic's codegen requires all types to implement Default, but there is
    /// no logical reason to construct a "default" RackId in real code, so
    /// we simply construct a bogus one here.
    #[allow(clippy::should_implement_trait)]
    #[deprecated(
        note = "Do not use `RackId::default()` directly; only implemented for prost interop"
    )]
    pub fn default() -> Self {
        Self::new(
            RackIdSource::ProductBoardChassisSerial,
            [0; 32],
            RackType::Rack,
        )
    }
}

impl DbPrimaryUuid for RackId {
    fn db_primary_uuid_name() -> &'static str {
        "rack_id"
    }
}

/// The hardware source from which the Rack ID is derived.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RackIdSource {
    /// The Rack ID was generated by hashing the TPM EkCertificate data.
    Tpm,
    /// The Rack ID was generated by the concatenation of product, board and chassis serial
    /// and hashing the resulting value.
    /// If any of those values is not available in DMI data, an empty
    /// string will be used instead. At least one serial number must have been
    /// available to generate this ID.
    ProductBoardChassisSerial,
}

impl RackIdSource {
    /// Returns the character that identifies the source type
    pub const fn id_char(self) -> char {
        match self {
            RackIdSource::Tpm => 't',
            RackIdSource::ProductBoardChassisSerial => 's',
        }
    }

    /// Parses the `RackIdSource` from a character
    pub fn from_id_char(c: char) -> Option<Self> {
        match c {
            c if c == Self::Tpm.id_char() => Some(Self::Tpm),
            c if c == Self::ProductBoardChassisSerial.id_char() => {
                Some(Self::ProductBoardChassisSerial)
            }
            _ => None,
        }
    }
}

/// Extra flags that are associated with the rack ID
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RackType {
    /// The Rack is a Rack
    Rack,
    /// The Rack is a Host
    Host,
}

impl RackType {
    /// Returns `true` if the Rack is a Rack
    pub fn is_rack(self) -> bool {
        self == RackType::Rack
    }

    /// Returns `true` if the Rack is a Host
    pub fn is_host(self) -> bool {
        self == RackType::Host
    }
}

impl std::fmt::Display for RackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackType::Rack => f.write_str("Rack"),
            RackType::Host => f.write_str("Host"),
        }
    }
}

impl RackType {
    /// Returns the character that identifies the flag
    pub const fn id_char(self) -> char {
        match self {
            RackType::Rack => 'r',
            RackType::Host => 'h',
        }
    }

    /// Parses the `RackType` from a character
    pub fn from_id_char(c: char) -> Option<Self> {
        match c {
            c if c == Self::Rack.id_char() => Some(Self::Rack),
            c if c == Self::Host.id_char() => Some(Self::Host),
            _ => None,
        }
    }
}

impl std::fmt::Display for RackId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `ps` is for power-shelf
        // `1` is a version identifier
        // The next 2 bytes `00` are reserved
        f.write_str("ps100")?;
        // Write the rack type
        f.write_char(self.ty.id_char())?;
        // The next character determines how the RackId is derived (`RackIdSource`)
        f.write_char(self.source.id_char())?;
        // Then follows the actual source data. self.hardware_id is guaranteed to have been written
        // from a valid string, so we can use from_utf8_unchecked.
        unsafe { f.write_str(std::str::from_utf8_unchecked(self.hardware_id.as_slice())) }
    }
}

impl From<uuid::Uuid> for RackId {
    fn from(value: uuid::Uuid) -> Self {
        // This is a fallback implementation - in practice, RackId should be created
        // from hardware hashes, not random UUIDs
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        Self::new(
            RackIdSource::Tpm, // Default source
            hash,
            RackType::Rack, // Default type
        )
    }
}

/// The length that is used for the prefix in Rack IDs
pub const RACK_ID_PREFIX_LENGTH: usize = 7;

/// The length of the hardware ID substring embedded in the Rack ID
///
/// Since it's a base32 encoded SHA256 (32byte), this makes 52 bytes
pub const RACK_ID_HARDWARE_ID_BASE32_LENGTH: usize = 52;

/// The length of a valid RackID
///
/// It is made up of the prefix length (5 bytes) plus the encoded hardware ID length
pub const RACK_ID_LENGTH: usize = RACK_ID_PREFIX_LENGTH + RACK_ID_HARDWARE_ID_BASE32_LENGTH;

#[derive(thiserror::Error, Debug, Clone)]
pub enum RackIdParseError {
    #[error("The Rack ID has an invalid length of {0}")]
    Length(usize),
    #[error("The Rack ID {0} has an invalid prefix")]
    Prefix(String),
    #[error("The Rack ID {0} has an invalid encoding")]
    Encoding(String),
}

impl FromStr for RackId {
    type Err = RackIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != RACK_ID_LENGTH {
            return Err(RackIdParseError::Length(s.len()));
        }
        // Check for version 1 and 2 reserved bytes
        if !s.starts_with("ps100") {
            return Err(RackIdParseError::Prefix(s.to_string()));
        }

        // Everything after the prefix needs to be valid base32
        let hardware_id = &s.as_bytes()[RACK_ID_PREFIX_LENGTH..];

        let mut hardware_hash: HardwareHash = [0u8; 32];
        match BASE32_DNSSEC.decode_mut(hardware_id, &mut hardware_hash) {
            Err(_) => return Err(RackIdParseError::Encoding(s.to_string())),
            Ok(size) if size != 32 => return Err(RackIdParseError::Encoding(s.to_string())),
            _ => {}
        }

        let ty = RackType::from_id_char(s.as_bytes()[5] as char)
            .ok_or_else(|| RackIdParseError::Prefix(s.to_string()))?;
        let source = RackIdSource::from_id_char(s.as_bytes()[6] as char)
            .ok_or_else(|| RackIdParseError::Prefix(s.to_string()))?;

        Ok(RackId::new(source, hardware_hash, ty))
    }
}

impl Serialize for RackId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RackId {
    fn deserialize<D>(deserializer: D) -> Result<RackId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let id = RackId::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(id)
    }
}

// Implement [`prost::Message`] manually so that we can be wire-compatible with the
// `.common.RackId` protobuf message, which is what we actually serialize. Do this by
// constructing a `legacy_rpc::RackId` and delegate all  [`prost::Message`] methods to it.
impl prost::Message for RackId {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        legacy_rpc::RackId::from(*self).encode_raw(buf);
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
        let mut legacy_message = legacy_rpc::RackId::from(*self);
        legacy_message.merge_field(tag, wire_type, buf, ctx)?;
        *self = RackId::from_str(&legacy_message.id)
            .map_err(|_| DecodeError::new(format!("Invalid rack id: {}", legacy_message.id)))?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        legacy_rpc::RackId::from(*self).encoded_len()
    }

    #[allow(deprecated)]
    fn clear(&mut self) {
        *self = RackId::default();
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
    ///
    /// This allows us to use [`super::RackId`] directly instead of having to convert it
    /// manually every time, while still interacting with peers that expect a `.common.RackId`
    /// to be serialized.
    #[derive(prost::Message)]
    pub struct RackId {
        #[prost(string, tag = "1")]
        pub id: String,
    }

    impl From<super::RackId> for RackId {
        fn from(value: crate::rack::RackId) -> Self {
            Self {
                id: value.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rack_id_round_trip() {
        let rack_id_str = "ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
        let rack_id = RackId::from_str(rack_id_str)
            .expect("Should have successfully converted from a valid string");
        let round_tripped = rack_id.to_string();
        assert_eq!(rack_id_str, round_tripped);
    }

    #[test]
    fn test_invalid_rack_ids() {
        match RackId::from_str("ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hc") {
            // one character short
            Err(RackIdParseError::Length(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a too-short rack ID should have failed"),
            Err(e) => panic!(
                "Converting from a too-short string should have failed with a length error, got {e}"
            ),
        }

        match RackId::from_str("PS100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(RackIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => {
                panic!("Converting from a rack ID with an invalid prefix should have failed")
            }
            Err(e) => panic!(
                "Converting from a rack ID with an invalid prefix should have failed with a Prefix error, got {e}"
            ),
        }

        match RackId::from_str("ps100xt038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(RackIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a rack ID with type `x` should have failed"),
            Err(e) => panic!(
                "Converting from a rack ID with type `x` should have failed with a Prefix error, got {e}"
            ),
        }

        match RackId::from_str("ps100dx038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(RackIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a rack ID with source `x` should have failed"),
            Err(e) => panic!(
                "Converting from a rack ID with source `x` should have failed with a Prefix error, got {e}"
            ),
        }

        match RackId::from_str("ps100ht038bg3qsho433vkg684heguv28!qaggmrsh2ugn1qk096n2c6hcg") {
            Err(RackIdParseError::Encoding(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a rack ID with a `!` should have failed"),
            Err(e) => panic!(
                "Converting from a rack ID with a `!` should have failed with an Encoding error, got {e}"
            ),
        }
    }
}
