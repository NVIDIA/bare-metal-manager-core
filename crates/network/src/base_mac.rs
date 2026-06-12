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
use std::str::FromStr;

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::sanitized_mac;

/// This type represent base mac that is reported by DPU. It is
/// serialized as MAC-address without ':' separator and can be parsed
/// from any MAC-address representation acceptable by sanitized_mac.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BaseMac(MacAddress);

impl BaseMac {
    pub fn to_mac(self) -> MacAddress {
        self.0
    }
}

impl From<MacAddress> for BaseMac {
    fn from(v: MacAddress) -> Self {
        Self(v)
    }
}

impl fmt::Display for BaseMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.bytes();
        let _ = write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        );
        Ok(())
    }
}

impl FromStr for BaseMac {
    type Err = eyre::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        sanitized_mac(s).map(BaseMac)
    }
}

impl Serialize for BaseMac {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BaseMac {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        Self::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))
    }
}

#[cfg(test)]
mod test {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    fn mac(bytes: [u8; 6]) -> BaseMac {
        BaseMac(MacAddress::new(bytes))
    }

    // --- Display: total, uppercase hex, no colons ---

    #[test]
    fn display_formats_uppercase_hex_without_colons() {
        check_values(
            [
                Check {
                    scenario: "ascending low bytes",
                    input: mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                    expect: "010203040506".to_string(),
                },
                Check {
                    scenario: "high bytes uppercase",
                    input: mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                    expect: "AABBCCDDEEFF".to_string(),
                },
                Check {
                    scenario: "all zeros",
                    input: mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    expect: "000000000000".to_string(),
                },
                Check {
                    scenario: "all ones",
                    input: mac([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                    expect: "FFFFFFFFFFFF".to_string(),
                },
                Check {
                    scenario: "single-digit bytes zero-padded",
                    input: mac([0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C]),
                    expect: "000A000B000C".to_string(),
                },
                Check {
                    scenario: "lowercase-hex digits rendered uppercase",
                    input: mac([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                    expect: "0A0B0C0D0E0F".to_string(),
                },
                Check {
                    scenario: "mixed bytes",
                    input: mac([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]),
                    expect: "FEDCBA987654".to_string(),
                },
            ],
            |m| m.to_string(),
        );
    }

    // --- to_mac: total getter, returns the wrapped MacAddress ---

    #[test]
    fn to_mac_returns_wrapped_address() {
        check_values(
            [
                Check {
                    scenario: "ascending bytes",
                    input: mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                    expect: MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                },
                Check {
                    scenario: "zeros",
                    input: mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    expect: MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                },
                Check {
                    scenario: "high bytes",
                    input: mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                    expect: MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                },
            ],
            |m| m.to_mac(),
        );
    }

    // --- From<MacAddress>: total conversion ---

    #[test]
    fn from_macaddress_wraps_unchanged() {
        check_values(
            [
                Check {
                    scenario: "ascending bytes",
                    input: MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                    expect: mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                },
                Check {
                    scenario: "high bytes",
                    input: MacAddress::new([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]),
                    expect: mac([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]),
                },
            ],
            BaseMac::from,
        );
    }

    // --- FromStr: fallible. eyre::Error is not PartialEq -> Fails + map_err(drop). ---
    // Ok rows compare on the rendered Display form; Err rows assert failure.

    #[test]
    fn from_str_parses_accepted_forms() {
        check_cases(
            [
                Case {
                    scenario: "raw hex, no separators",
                    input: "010203040506",
                    expect: Yields("010203040506".to_string()),
                },
                Case {
                    scenario: "colon separated",
                    input: "01:02:03:04:05:06",
                    expect: Yields("010203040506".to_string()),
                },
                Case {
                    scenario: "space separated",
                    input: "01 02 03 04 05 06",
                    expect: Yields("010203040506".to_string()),
                },
                Case {
                    scenario: "hyphen separated",
                    input: "01-02-03-04-05-06",
                    expect: Yields("010203040506".to_string()),
                },
                Case {
                    scenario: "mixed case normalized to uppercase",
                    input: "AaBbCcDdEeFf",
                    expect: Yields("AABBCCDDEEFF".to_string()),
                },
                Case {
                    scenario: "lowercase normalized to uppercase",
                    input: "aabbccddeeff",
                    expect: Yields("AABBCCDDEEFF".to_string()),
                },
                Case {
                    scenario: "all zeros",
                    input: "000000000000",
                    expect: Yields("000000000000".to_string()),
                },
                Case {
                    scenario: "all ff",
                    input: "ffffffffffff",
                    expect: Yields("FFFFFFFFFFFF".to_string()),
                },
                Case {
                    scenario: "runs of whitespace between bytes",
                    input: "a088c2    460c68",
                    expect: Yields("A088C2460C68".to_string()),
                },
                Case {
                    // Dots are non-hex, so they're stripped and the 12-hex-digit
                    // residue is accepted -- a side effect of the stripping, not a
                    // deliberately supported separator.
                    scenario: "non-hex separators stripped",
                    input: "0a.0b.0c.0d.0e.0f",
                    expect: Yields("0A0B0C0D0E0F".to_string()),
                },
                Case {
                    scenario: "empty string has zero hex digits",
                    input: "",
                    expect: Fails,
                },
                Case {
                    scenario: "too short by one byte",
                    input: "0102030405",
                    expect: Fails,
                },
                Case {
                    scenario: "too long by one byte",
                    input: "0102030405060708",
                    expect: Fails,
                },
                Case {
                    scenario: "one extra hex digit",
                    input: "0102030405067",
                    expect: Fails,
                },
                Case {
                    scenario: "only non-hex characters",
                    input: "invalid-mac",
                    expect: Fails,
                },
                Case {
                    scenario: "non-hex letters dropped leaving too few digits",
                    input: "gg:hh:ii:jj:kk:ll",
                    expect: Fails,
                },
                Case {
                    scenario: "whitespace only",
                    input: "   ",
                    expect: Fails,
                },
            ],
            |s| BaseMac::from_str(s).map(|m| m.to_string()).map_err(drop),
        );
    }

    #[test]
    fn from_str_rejects_with_invalid_length_message() {
        // Overlaps with `from_str_parses_accepted_forms` on the same inputs by
        // design: that test pins *which* inputs fail, this one pins *what the
        // error message says*.
        check_cases(
            [
                Case {
                    scenario: "too short reports invalid length",
                    input: ("0102030405", &["Invalid stripped MAC length"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "too long reports invalid length",
                    input: ("0102030405060708", &["Invalid stripped MAC length"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "empty reports invalid length",
                    input: ("", &["Invalid stripped MAC length"][..]),
                    expect: Yields(true),
                },
            ],
            |(value, tokens)| {
                let produced = BaseMac::from_str(value).unwrap_err().to_string();
                Ok::<_, ()>(tokens.iter().all(|t| produced.contains(t)))
            },
        );
    }

    // --- Serialize: produces the colon-free uppercase Display string, JSON-quoted. ---

    #[test]
    fn serialize_emits_quoted_display_string() {
        check_cases(
            [
                Case {
                    scenario: "ascending bytes",
                    input: mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                    expect: Yields("\"010203040506\"".to_string()),
                },
                Case {
                    scenario: "high bytes uppercase",
                    input: mac([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]),
                    expect: Yields("\"FEDCBA987654\"".to_string()),
                },
                Case {
                    scenario: "zeros",
                    input: mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    expect: Yields("\"000000000000\"".to_string()),
                },
            ],
            |m| serde_json::to_string(&m).map_err(drop),
        );
    }

    // --- Deserialize: fallible. serde_json::Error is not relied on for equality. ---

    #[test]
    fn deserialize_parses_accepted_json_strings() {
        check_cases(
            [
                Case {
                    scenario: "raw hex string",
                    input: "\"0a0b0c0d0e0f\"",
                    expect: Yields("0A0B0C0D0E0F".to_string()),
                },
                Case {
                    scenario: "colon separated string",
                    input: "\"11:22:33:44:55:66\"",
                    expect: Yields("112233445566".to_string()),
                },
                Case {
                    scenario: "uppercase round-trips",
                    input: "\"FEDCBA987654\"",
                    expect: Yields("FEDCBA987654".to_string()),
                },
                Case {
                    scenario: "non-string json number",
                    input: "1234",
                    expect: Fails,
                },
                Case {
                    scenario: "null",
                    input: "null",
                    expect: Fails,
                },
                Case {
                    scenario: "invalid mac text",
                    input: "\"invalid-mac\"",
                    expect: Fails,
                },
                Case {
                    scenario: "too-short string",
                    input: "\"0102030405\"",
                    expect: Fails,
                },
                Case {
                    scenario: "empty string",
                    input: "\"\"",
                    expect: Fails,
                },
            ],
            |json| {
                serde_json::from_str::<BaseMac>(json)
                    .map(|m| m.to_string())
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn deserialize_failure_carries_invalid_length_message() {
        check_cases(
            [
                Case {
                    scenario: "invalid text reports length",
                    input: ("\"invalid-mac\"", &["Invalid stripped MAC length"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "short string reports length",
                    input: ("\"0102030405\"", &["Invalid stripped MAC length"][..]),
                    expect: Yields(true),
                },
            ],
            |(json, tokens)| {
                let produced = serde_json::from_str::<BaseMac>(json)
                    .unwrap_err()
                    .to_string();
                Ok::<_, ()>(tokens.iter().all(|t| produced.contains(t)))
            },
        );
    }

    // --- Round trip: serialize then deserialize yields the original value. ---

    #[test]
    fn round_trips_through_json() {
        check_cases(
            [
                Case {
                    scenario: "high bytes",
                    input: mac([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]),
                    expect: Yields(mac([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54])),
                },
                Case {
                    scenario: "ascending bytes",
                    input: mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                    expect: Yields(mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
                },
                Case {
                    scenario: "zeros",
                    input: mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    expect: Yields(mac([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
                },
            ],
            |original| {
                let serialized = serde_json::to_string(&original).map_err(drop)?;
                serde_json::from_str::<BaseMac>(&serialized).map_err(drop)
            },
        );
    }
}
