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
    use super::*;

    #[test]
    fn base_mac_display_formats_without_colons() {
        let mac = BaseMac(MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(format!("{}", mac), "010203040506");
    }

    #[test]
    fn base_mac_display_uppercase_hex() {
        let mac = BaseMac(MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        assert_eq!(format!("{}", mac), "AABBCCDDEEFF");
    }

    #[test]
    fn base_mac_from_str_parses_raw_hex() {
        let mac = BaseMac::from_str("010203040506").expect("valid MAC");
        assert_eq!(mac.0, MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
    }

    #[test]
    fn base_mac_from_str_parses_colon_separated() {
        let mac = BaseMac::from_str("01:02:03:04:05:06").expect("valid MAC");
        assert_eq!(mac.0, MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
    }

    #[test]
    fn base_mac_from_str_parses_with_spaces() {
        let mac = BaseMac::from_str("01 02 03 04 05 06").expect("valid MAC");
        assert_eq!(mac.0, MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
    }

    #[test]
    fn base_mac_from_str_parses_mixed_case() {
        let mac = BaseMac::from_str("AaBbCcDdEeFf").expect("valid MAC");
        assert_eq!(mac.0, MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn base_mac_from_str_rejects_invalid_length() {
        let err = BaseMac::from_str("0102030405").unwrap_err();
        assert!(err.to_string().contains("Invalid stripped MAC length"));
    }

    #[test]
    fn base_mac_from_str_rejects_too_long() {
        let err = BaseMac::from_str("0102030405060708").unwrap_err();
        assert!(err.to_string().contains("Invalid stripped MAC length"));
    }

    #[test]
    fn base_mac_serialization_without_colons() {
        let mac = BaseMac(MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        let serialized = serde_json::to_string(&mac).expect("serialization");
        assert_eq!(serialized, "\"010203040506\"");
    }

    #[test]
    fn base_mac_serialization_uppercase_hex() {
        let mac = BaseMac(MacAddress::new([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]));
        let serialized = serde_json::to_string(&mac).expect("serialization");
        assert_eq!(serialized, "\"FEDCBA987654\"");
    }

    #[test]
    fn base_mac_deserialization_parses_raw_hex_string() {
        let json = "\"0a0b0c0d0e0f\"";
        let mac: BaseMac = serde_json::from_str(json).expect("deserialize raw hex");
        assert_eq!(mac.to_string(), "0A0B0C0D0E0F");
    }

    #[test]
    fn base_mac_deserialization_parses_colon_separated() {
        let json = "\"11:22:33:44:55:66\"";
        let mac: BaseMac = serde_json::from_str(json).expect("deserialize json");
        assert_eq!(mac.to_string(), "112233445566");
    }

    #[test]
    fn base_mac_round_trip_serialization() {
        let original = BaseMac(MacAddress::new([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54]));
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: BaseMac = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn base_mac_deserialization_fails_on_invalid_input() {
        let json = "\"invalid-mac\"";
        let err = serde_json::from_str::<BaseMac>(json).unwrap_err();
        assert!(err.to_string().contains("Invalid stripped MAC length"));
    }

    #[test]
    fn base_mac_deserialization_fails_on_short_input() {
        let json = "\"0102030405\"";
        let err = serde_json::from_str::<BaseMac>(json).unwrap_err();
        assert!(err.to_string().contains("Invalid stripped MAC length"));
    }
}
