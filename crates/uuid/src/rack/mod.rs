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
use sqlx::Row;

use crate::DbPrimaryUuid;

/// The `RackId` uniquely identifies a rack that is managed by the system.
///
/// `RackId` is a newtype over `String`. The value is typically provided by
/// an external Datacenter Inventory Manager (DCIM) and can be in any format
/// that the DCIM uses (e.g. "P20", "rack-42-us-west", or the legacy
/// `ps100...` encoded format).
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[serde(transparent)]
#[cfg_attr(feature = "sqlx", sqlx(transparent))]
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

#[cfg(feature = "sqlx")]
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for RackId {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let id: RackId = row.try_get::<RackId, _>(0)?;
        Ok(id)
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
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[serde(transparent)]
#[cfg_attr(feature = "sqlx", sqlx(transparent))]
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum ParseFailure {
        Empty,
    }

    fn parse_rack_id(input: &str) -> Result<String, ParseFailure> {
        RackId::from_str(input)
            .map(|id| id.to_string())
            .map_err(|err| match err {
                RackIdParseError::Empty => ParseFailure::Empty,
            })
    }

    fn parse_rack_profile_id(input: &str) -> Result<String, ParseFailure> {
        RackProfileId::from_str(input)
            .map(|id| id.to_string())
            .map_err(|err| match err {
                RackIdParseError::Empty => ParseFailure::Empty,
            })
    }

    fn deserialize_rack_id(input: &str) -> Result<String, ()> {
        serde_json::from_str::<RackId>(input)
            .map(|id| id.to_string())
            .map_err(|_| ())
    }

    fn deserialize_rack_profile_id(input: &str) -> Result<String, ()> {
        serde_json::from_str::<RackProfileId>(input)
            .map(|id| id.to_string())
            .map_err(|_| ())
    }

    #[test]
    fn test_rack_id_parse_cases() {
        check_cases(
            [
                Case {
                    scenario: "legacy ps100-encoded rack ID",
                    input: "ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg",
                    expect: Yields(
                        "ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg".to_string(),
                    ),
                },
                Case {
                    scenario: "DCIM rack name",
                    input: "P20",
                    expect: Yields("P20".to_string()),
                },
                Case {
                    scenario: "regional rack name",
                    input: "rack-42-us-west-2",
                    expect: Yields("rack-42-us-west-2".to_string()),
                },
                Case {
                    scenario: "descriptive rack name",
                    input: "i-am-just-a-rack-id",
                    expect: Yields("i-am-just-a-rack-id".to_string()),
                },
                Case {
                    scenario: "empty rack ID",
                    input: "",
                    expect: FailsWith(ParseFailure::Empty),
                },
            ],
            parse_rack_id,
        );
    }

    #[test]
    fn test_rack_id_conversions() {
        check_values(
            [
                Check {
                    scenario: "new",
                    input: RackId::new("test-rack"),
                    expect: (
                        "test-rack".to_string(),
                        "test-rack".to_string(),
                        "test-rack".to_string(),
                    ),
                },
                Check {
                    scenario: "from str",
                    input: RackId::from("another-rack"),
                    expect: (
                        "another-rack".to_string(),
                        "another-rack".to_string(),
                        "another-rack".to_string(),
                    ),
                },
                Check {
                    scenario: "from string",
                    input: RackId::from(String::from("string-rack")),
                    expect: (
                        "string-rack".to_string(),
                        "string-rack".to_string(),
                        "string-rack".to_string(),
                    ),
                },
            ],
            |rack_id| {
                (
                    rack_id.as_str().to_string(),
                    rack_id.to_string(),
                    rack_id.as_ref().to_string(),
                )
            },
        );
    }

    #[test]
    fn test_rack_id_serde_cases() {
        check_cases(
            [
                Case {
                    scenario: "valid string",
                    input: "\"my-custom-rack\"",
                    expect: Yields("my-custom-rack".to_string()),
                },
                Case {
                    scenario: "empty string",
                    input: "\"\"",
                    expect: Yields(String::new()),
                },
                Case {
                    scenario: "non-string JSON",
                    input: "42",
                    expect: Fails,
                },
            ],
            deserialize_rack_id,
        );

        let serialized = serde_json::to_string(&RackId::new("my-custom-rack"))
            .expect("failed to serialize rack ID");
        assert_eq!(serialized, "\"my-custom-rack\"");
    }

    #[test]
    fn test_rack_profile_id_parse_cases() {
        check_cases(
            [
                Case {
                    scenario: "rack profile name",
                    input: "NVL72",
                    expect: Yields("NVL72".to_string()),
                },
                Case {
                    scenario: "lowercase rack profile name",
                    input: "nvl36",
                    expect: Yields("nvl36".to_string()),
                },
                Case {
                    scenario: "empty rack profile ID",
                    input: "",
                    expect: FailsWith(ParseFailure::Empty),
                },
            ],
            parse_rack_profile_id,
        );
    }

    #[test]
    fn test_rack_profile_id_conversions() {
        check_values(
            [
                Check {
                    scenario: "new",
                    input: RackProfileId::new("NVL72"),
                    expect: (
                        "NVL72".to_string(),
                        "NVL72".to_string(),
                        "NVL72".to_string(),
                    ),
                },
                Check {
                    scenario: "from str",
                    input: RackProfileId::from("NVL36"),
                    expect: (
                        "NVL36".to_string(),
                        "NVL36".to_string(),
                        "NVL36".to_string(),
                    ),
                },
                Check {
                    scenario: "from string",
                    input: RackProfileId::from(String::from("GB200")),
                    expect: (
                        "GB200".to_string(),
                        "GB200".to_string(),
                        "GB200".to_string(),
                    ),
                },
            ],
            |profile_id| {
                (
                    profile_id.as_str().to_string(),
                    profile_id.to_string(),
                    profile_id.as_ref().to_string(),
                )
            },
        );
    }

    #[test]
    fn test_rack_profile_id_serde_cases() {
        check_cases(
            [
                Case {
                    scenario: "valid string",
                    input: "\"NVL72\"",
                    expect: Yields("NVL72".to_string()),
                },
                Case {
                    scenario: "empty string",
                    input: "\"\"",
                    expect: Yields(String::new()),
                },
                Case {
                    scenario: "non-string JSON",
                    input: "42",
                    expect: Fails,
                },
            ],
            deserialize_rack_profile_id,
        );

        let serialized = serde_json::to_string(&RackProfileId::new("NVL72"))
            .expect("failed to serialize rack profile ID");
        assert_eq!(serialized, "\"NVL72\"");
    }
}
