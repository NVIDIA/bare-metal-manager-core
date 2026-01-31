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

use super::DbPrimaryUuid;

static MACHINE_ID_PREFIX: &str = "fm100";

#[cfg(feature = "sqlx")]
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgHasArrayType, PgTypeInfo},
    {Database, Postgres, Row},
};

use crate::typed_uuids::{TypedUuid, UuidSubtype};

/// Marker type for MachineInterfaceId
pub struct MachineInterfaceIdMarker;

impl UuidSubtype for MachineInterfaceIdMarker {
    const TYPE_NAME: &'static str = "MachineInterfaceId";
}

/// MachineInterfaceId is a strongly typed UUID for machine interfaces.
pub type MachineInterfaceId = TypedUuid<MachineInterfaceIdMarker>;

/// This is a fixed-size hash of the machine hardware.
pub type HardwareHash = [u8; 32];
/// This is the base32-encoded representation of the hardware hash. It is a fixed size instead of a
/// String so that we can implement the Copy trait.
pub type HardwareIdBase32 = [u8; MACHINE_ID_HARDWARE_ID_BASE32_LENGTH];

/// The `MachineId` uniquely identifies a machine that is managed by the Forge system
///
/// `MachineId`s are derived from a hardware fingerprint, and are thereby
/// globally unique.
///
/// MachineIds are using an encoding which makes them valid DNS names.
/// This requires the use of lowercase characters only.
///
/// Examples for MachineIds can be:
/// - fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
/// - fm100dtjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
/// - fm100hsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g
/// - fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g
/// - fm100ptjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MachineId {
    /// The hardware source from which the Machine ID was derived
    source: MachineIdSource,
    /// The Machine hash which was derived via hashing from the hardware piece
    /// that is indicated in `source`, encoded via base32. Must be valid utf-8.
    hardware_id: HardwareIdBase32,
    /// The Type of the Machine
    ty: MachineType,
}

impl Ord for MachineId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for MachineId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Implement [`prost::Message`] manually so that we can be wire-compatible with the
// `.common.MachineId` protobuf message, which is what we actually serialize. Do this by
// constructing a `legacy_rpc::MachineId` and delegate all  [`prost::Message`] methods to it.
impl prost::Message for MachineId {
    fn encode_raw(&self, buf: &mut impl BufMut)
    where
        Self: Sized,
    {
        legacy_rpc::MachineId::from(*self).encode_raw(buf);
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
        let mut legacy_message = legacy_rpc::MachineId::from(*self);
        legacy_message.merge_field(tag, wire_type, buf, ctx)?;
        *self = MachineId::from_str(&legacy_message.id)
            .map_err(|_| DecodeError::new(format!("Invalid machine id: {}", legacy_message.id)))?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        legacy_rpc::MachineId::from(*self).encoded_len()
    }

    #[allow(deprecated)]
    fn clear(&mut self) {
        *self = MachineId::default();
    }
}

mod legacy_rpc {
    /// Backwards compatiblity shim for [`super::MachineId`] to be sent as a protobuf message in a
    /// way that is compatible with the `.common.MachineId` message, which is defined as:
    ///
    /// ```ignore
    /// message MachineId {
    ///     string id = 1;
    /// }
    /// ```
    ///
    /// This allows us to use [`super::MachineId`] directly instead of having to convert it
    /// manually every time, while still interacting with peers that expect a `.common.MachineId`
    /// to be serialized.
    #[derive(prost::Message)]
    pub struct MachineId {
        #[prost(string, tag = "1")]
        pub id: String,
    }

    impl From<super::MachineId> for MachineId {
        fn from(value: crate::machine::MachineId) -> Self {
            Self {
                id: value.to_string(),
            }
        }
    }
}

impl Default for MachineId {
    #[allow(deprecated)]
    fn default() -> Self {
        Self::default()
    }
}

impl Debug for MachineId {
    // The derived Debug implementation is messy, just output the string representation even when
    // debugging.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

// Make MachineId bindable directly into a sqlx query
#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for MachineId {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        buf.extend(self.to_string().as_bytes());
        Ok(sqlx::encode::IsNull::No)
    }
}

#[cfg(feature = "sqlx")]
impl<'r, DB> sqlx::Decode<'r, DB> for MachineId
where
    DB: sqlx::Database,
    String: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::database::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let str_id: String = String::decode(value)?;
        Ok(MachineId::from_str(&str_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?)
    }
}

#[cfg(feature = "sqlx")]
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for MachineId {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let id: MachineId = row.try_get(0)?;
        Ok(id)
    }
}

#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for MachineId
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
impl PgHasArrayType for MachineId {
    fn array_type_info() -> PgTypeInfo {
        <&str as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <&str as PgHasArrayType>::array_compatible(ty)
    }
}

impl MachineId {
    pub fn new(source: MachineIdSource, hardware_hash: HardwareHash, ty: MachineType) -> MachineId {
        // BASE32_DNSSEC is chosen to just generate lowercase characters and
        // numbers - which will result in valid DNS names for MachineIds.
        let encoded = BASE32_DNSSEC.encode(&hardware_hash);
        assert_eq!(encoded.len(), MACHINE_ID_HARDWARE_ID_BASE32_LENGTH);

        Self {
            source,
            hardware_id: encoded.as_bytes().try_into().unwrap(),
            ty,
        }
    }

    /// The hardware source from which the Machine ID was derived
    pub fn source(&self) -> MachineIdSource {
        self.source
    }

    /// The type of the Machine
    pub fn machine_type(&self) -> MachineType {
        self.ty
    }

    /// Generate Remote ID based on machineID.
    /// Remote Id is inserted by dhcrelay on DPU in each DHCP request sent by host.
    /// This field is used only for DPU.
    pub fn remote_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_string().as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        BASE32_DNSSEC.encode(&hash)
    }

    /// Note: Never use this! Tonic's codegen requires all types to implement Default, but there is
    /// no logical reason to construct a "default" MachineId in real code, so we simply construct a
    /// bogus one here.
    #[allow(clippy::should_implement_trait)]
    #[deprecated(
        note = "Do not use `MachineId::default()` directly; only implemented for prost interop"
    )]
    pub fn default() -> Self {
        Self::new(
            MachineIdSource::ProductBoardChassisSerial,
            [0; 32],
            MachineType::Host,
        )
    }
}

impl DbPrimaryUuid for MachineId {
    fn db_primary_uuid_name() -> &'static str {
        "machine_id"
    }
}

/// The hardware source from which the Machine ID is derived
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MachineIdSource {
    /// The Machine ID was generated by hashing the TPM EkCertificate data.
    Tpm,
    /// The Machine ID was generated by the concatenation of product, board and chassis serial
    /// and hashing the resulting value.
    /// If any of those values is not available in DMI data, an empty
    /// string will be used instead. At least one serial number must have been
    /// available to generate this ID.
    ProductBoardChassisSerial,
}

impl MachineIdSource {
    /// Returns the character that identifies the source type
    pub const fn id_char(self) -> char {
        match self {
            MachineIdSource::Tpm => 't',
            MachineIdSource::ProductBoardChassisSerial => 's',
        }
    }

    /// Parses the `MachineIdSource` from a character
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

/// Extra flags that are associated with the machine ID
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MachineType {
    // The Machine is a DPU
    Dpu,
    /// The Machine is a Forge managed host
    Host,
    /// The Machine is a host whose existence had been predicated by a DPU
    /// being detected by Forge.
    /// However the actual Machine ID of the host is not yet known, since the
    /// Machine hardware details are not yet known. Therefore a **temporary**
    /// ID is created. The temporary ID is derived from the DPU Machine ID,
    /// and carries its hardware identifier, which will be encoded in the
    /// `source` and `hardware_id` fields.
    ///
    /// Once the hardware fingerprint of the host is known, the Machine will
    /// obtain a new `MachineId` with `MachineType::Host`
    PredictedHost,
}

impl MachineType {
    /// Returns `true` if the Machine is a DPU
    pub fn is_dpu(self) -> bool {
        self == MachineType::Dpu
    }

    /// Returns the [`MachineType`] this ID string matches, if any.
    pub fn from_id_string(s: &str) -> Option<Self> {
        MachineId::from_str(s).ok().map(|i| i.ty)
    }

    /// Returns `true` if the Machine is a Host
    ///
    /// This only returns `true` for hosts which actually have been discovered,
    /// and not for temporary (predicted) hosts.
    pub fn is_host(self) -> bool {
        self == MachineType::Host
    }

    pub fn is_predicted_host(self) -> bool {
        self == MachineType::PredictedHost
    }

    /// Description of this machine type when used by metrics (lowercased, intended to be machine-readable)
    pub fn metrics_value(&self) -> &'static str {
        match self {
            MachineType::Dpu => "dpu",
            MachineType::Host => "host",
            MachineType::PredictedHost => "predictedhost",
        }
    }

    pub fn id_prefix(self) -> &'static str {
        match self {
            MachineType::Dpu => "fm100d",
            MachineType::Host => "fm100h",
            MachineType::PredictedHost => "fm100p",
        }
    }
}

impl std::fmt::Display for MachineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineType::Dpu => f.write_str("DPU"),
            MachineType::Host => f.write_str("Host"),
            MachineType::PredictedHost => f.write_str("Host (Predicted)"),
        }
    }
}

impl MachineType {
    /// Returns the character that identifies the flag
    pub const fn id_char(self) -> char {
        match self {
            MachineType::Dpu => 'd',
            MachineType::Host => 'h',
            MachineType::PredictedHost => 'p',
        }
    }

    /// Parses the `MachineType` from a character
    pub fn from_id_char(c: char) -> Option<Self> {
        match c {
            c if c == Self::Dpu.id_char() => Some(Self::Dpu),
            c if c == Self::Host.id_char() => Some(Self::Host),
            c if c == Self::PredictedHost.id_char() => Some(Self::PredictedHost),
            _ => None,
        }
    }
}

impl std::fmt::Display for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `fm` is for forge-machine
        // `1` is a version identifier
        // The next 2 bytes `00` are reserved
        f.write_str(MACHINE_ID_PREFIX)?;
        // Write the machine type
        f.write_char(self.ty.id_char())?;
        // The next character determines how the MachineId is derived (`MachineIdSource`)
        f.write_char(self.source.id_char())?;
        // Then follows the actual source data. self.hardware_id is guaranteed to have been written
        // from a valid string, so we can use from_utf8_unchecked.
        unsafe { f.write_str(std::str::from_utf8_unchecked(self.hardware_id.as_slice())) }
    }
}

/// The length that is used for the prefix in Machine IDs
pub const MACHINE_ID_PREFIX_LENGTH: usize = 7;

/// The length of the hardware ID substring embedded in the Machine ID
///
/// Since it's a base32 encoded SHA256 (32byte), this makes 52 bytes
pub const MACHINE_ID_HARDWARE_ID_BASE32_LENGTH: usize = 52;

/// The length of a valid MachineID
///
/// It is made up of the prefix length (5 bytes) plus the encoded hardware ID length
pub const MACHINE_ID_LENGTH: usize =
    MACHINE_ID_PREFIX_LENGTH + MACHINE_ID_HARDWARE_ID_BASE32_LENGTH;

#[derive(thiserror::Error, Debug, Clone)]
pub enum MachineIdParseError {
    #[error("The Machine ID has an invalid length of {0}")]
    Length(usize),
    #[error("The Machine ID {0} has an invalid prefix")]
    Prefix(String),
    #[error("The Machine ID {0} has an invalid encoding")]
    Encoding(String),
}

impl FromStr for MachineId {
    type Err = MachineIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != MACHINE_ID_LENGTH {
            return Err(MachineIdParseError::Length(s.len()));
        }
        // Check for version 1 and 2 reserved bytes
        if !s.starts_with(MACHINE_ID_PREFIX) {
            return Err(MachineIdParseError::Prefix(s.to_string()));
        }

        // Everything after the prefix needs to be valid base32
        let hardware_id = &s.as_bytes()[MACHINE_ID_PREFIX_LENGTH..];

        let mut hardware_hash: HardwareHash = [0u8; 32];
        match BASE32_DNSSEC.decode_mut(hardware_id, &mut hardware_hash) {
            Err(_) => return Err(MachineIdParseError::Encoding(s.to_string())),
            Ok(size) if size != 32 => return Err(MachineIdParseError::Encoding(s.to_string())),
            _ => {}
        }

        let ty = MachineType::from_id_char(s.as_bytes()[5] as char)
            .ok_or_else(|| MachineIdParseError::Prefix(s.to_string()))?;
        let source = MachineIdSource::from_id_char(s.as_bytes()[6] as char)
            .ok_or_else(|| MachineIdParseError::Prefix(s.to_string()))?;

        Ok(MachineId::new(source, hardware_hash, ty))
    }
}

impl Serialize for MachineId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MachineId {
    fn deserialize<D>(deserializer: D) -> Result<MachineId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let id = MachineId::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_id_round_trip() {
        let machine_id_str = "fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg";
        let machine_id = MachineId::from_str(machine_id_str)
            .expect("Should have successfully converted from a valid string");
        let round_tripped = machine_id.to_string();
        assert_eq!(machine_id_str, round_tripped);
    }

    #[test]
    fn test_invalid_machine_ids() {
        match MachineId::from_str("fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hc") {
            // one character short
            Err(MachineIdParseError::Length(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a too-short machine ID should have failed"),
            Err(e) => panic!(
                "Converting from a too-short string should have failed with a length error, got {e}"
            ),
        }

        match MachineId::from_str("FM100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(MachineIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => {
                panic!("Converting from a machine ID with an invalid prefix should have failed")
            }
            Err(e) => panic!(
                "Converting from a machine ID with an invalid prefix should have failed with a Prefix error, got {e}"
            ),
        }

        match MachineId::from_str("fm100xt038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(MachineIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a machine ID with type `x` should have failed"),
            Err(e) => panic!(
                "Converting from a machine ID with type `x` should have failed with a Prefix error, got {e}"
            ),
        }

        match MachineId::from_str("fm100dx038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg") {
            Err(MachineIdParseError::Prefix(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a machine ID with source `x` should have failed"),
            Err(e) => panic!(
                "Converting from a machine ID with source `x` should have failed with a Prefix error, got {e}"
            ),
        }

        match MachineId::from_str("fm100ht038bg3qsho433vkg684heguv28!qaggmrsh2ugn1qk096n2c6hcg") {
            Err(MachineIdParseError::Encoding(_)) => {} // Expect an error
            Ok(_) => panic!("Converting from a machine ID with a `!` should have failed"),
            Err(e) => panic!(
                "Converting from a machine ID with a `!` should have failed with an Encoding error, got {e}"
            ),
        }
    }
}
