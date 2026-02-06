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

use std::str::FromStr;

use mac_address::{MacAddress, MacParseError};
use serde::Deserialize;
use serde::de::Deserializer;

pub mod ip;

/// virtualization is a module specific to shared code around
/// network virtualization, where shared means shared between
/// different components, where components currently means
/// Carbide API and the [DPU] agent.
pub mod virtualization;

const STRIPPED_MAC_LENGTH: usize = 12;

/// MELLANOX_SF_VF_MAC_ADDRESS_IN exists to really make it obvious
/// that the MAC address reported to topology data for SFs and VFs
/// comes in as ch:64.
pub const MELLANOX_SF_VF_MAC_ADDRESS_IN: &str = "ch:64";

/// MELLANOX_SF_VF_MAC_ADDRESS_OUT exists to really make it obvious
/// that we take MELLANOX_SF_VF_MAC_ADDRESS_IN and rewrite it out
/// as this.
pub const MELLANOX_SF_VF_MAC_ADDRESS_OUT: &str = "00:00:00:00:00:64";

/// sanitized_mac takes a potentially nasty input MAC address
/// string (e.g. `"a088c2    460c68"`, cleans up anything that
/// isn't base-16, adds colons, and returns you a nice MAC address
/// in the format of a mac_address::MacAddress.
///
///
/// For example:
///   `"a088c2    460c68"` -> `a088c2460c68` -> `A0:88:C2:46:0C:68`
///   `aa:bb:cc:DD:ee:ff`  -> `aabbccDDeeff` -> `AA:BB:CC:DD:EE:FF`
pub fn sanitized_mac(input_mac: &String) -> eyre::Result<MacAddress> {
    // First, strip out anything that isn't hex ([0-9A-Fa-f]),
    // which can be done with is_ascii_hexdigit().
    //
    // This will also strip out [g-zG-Z], so if we wanted to
    // error on that, and not silently drop them, this would
    // need to be changed. However, cases like that should
    // result in a bad STRIPPED_MAC_LENGTH anyway.
    let stripped_mac: String = input_mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if stripped_mac.len() != STRIPPED_MAC_LENGTH {
        return Err(eyre::eyre!(
            "Invalid stripped MAC length: {} (input: {}, output: {})",
            stripped_mac.len(),
            input_mac,
            stripped_mac,
        ));
    }

    // And then shove some colons back in, and we're done!
    let sanitized_mac =
        stripped_mac
            .chars()
            .enumerate()
            .fold(String::new(), |mut sanitized, (index, char)| {
                if index > 0 && index % 2 == 0 {
                    sanitized.push(':');
                }
                sanitized.push(char);
                sanitized
            });

    MacAddress::from_str(&sanitized_mac).map_err(|e| eyre::eyre!("Failed to initialize MacAddress from sanitized MAC: {} (input: {}, stripped: {}, sanitized: {}", e, input_mac, stripped_mac, sanitized_mac))
}

/// deserialize_mlx_mac exists due to an interesting behavior
/// of Mellanox cards -- SFs and VFs (i.e. interfaces that aren't
/// the physical interface) report a MAC address of "ch:64",
/// which isn't a real MAC address. Unfortnuately, this breaks
/// MAC address validation + serialization for everyone else for
/// this field.
///
/// In other cases, it will report an empty string, so that's
/// another case we need to deal with.
///
/// So, instead of doing away with validation entirely, this
/// custom deserialization function exists to rewrite ch:64 as
/// 00:::::64 -- this is used for both ingestion (as in, when
/// topology data is sent to us as JSON), and for reading legacy
/// data from the database; at this point, serialization out to
/// the database will ALWAYS be a valid MAC, since the field is
/// a MacAddress now, so we just care about deserialization.
///
/// Fwiw, we obviously don't use ch:64 as an actual MAC
/// address, but still want us some insight in topology
/// data that its a special case, while still meeting the
/// requirements of being a valid MAC address.
pub fn deserialize_mlx_mac<'a, D>(deserializer: D) -> Result<MacAddress, D::Error>
where
    D: Deserializer<'a>,
{
    let input_value = String::deserialize(deserializer)?;
    let mac_address = deserialize_input_mac_to_address(&input_value).map_err(|e| {
        serde::de::Error::custom(format!(
            "failed to parse input mac_address({input_value}): {e}"
        ))
    })?;

    Ok(mac_address)
}

pub fn deserialize_optional_mlx_mac<'a, D>(deserializer: D) -> Result<Option<MacAddress>, D::Error>
where
    D: Deserializer<'a>,
{
    let optional_value: Option<String> = Option::deserialize(deserializer)?;

    let mac_address: Option<MacAddress> = match optional_value {
        Some(input_value) => {
            let mac_address = deserialize_input_mac_to_address(&input_value).map_err(|e| {
                serde::de::Error::custom(format!(
                    "failed to parse input mac_address({input_value}): {e}"
                ))
            })?;
            Some(mac_address)
        }
        None => None,
    };

    Ok(mac_address)
}

/// deserialize_input_mac_to_address is a common input to MAC conversion
/// function used by deserialize_mlx_mac and deserialize_optional_mlx_mac.
pub fn deserialize_input_mac_to_address(input_value: &String) -> Result<MacAddress, MacParseError> {
    let mac_string = if input_value == MELLANOX_SF_VF_MAC_ADDRESS_IN {
        MELLANOX_SF_VF_MAC_ADDRESS_OUT.to_string()
    } else if input_value.is_empty() {
        "00:00:00:00:00:00".to_string()
    } else {
        input_value.clone()
    };

    let mac_address: MacAddress = mac_string.parse()?;
    Ok(mac_address)
}
#[cfg(test)]
mod tests {
    use super::{MELLANOX_SF_VF_MAC_ADDRESS_OUT, deserialize_input_mac_to_address, sanitized_mac};

    #[test]
    fn test_gross_redfish_mac() {
        let gross_redfish_mac = "\"a088c2    460c68\"".to_string();
        assert_eq!(
            sanitized_mac(&gross_redfish_mac).unwrap().to_string(),
            "A0:88:C2:46:0C:68".to_string()
        );
    }

    #[test]
    fn test_smashed_mac() {
        let smashed_mac = "000000ABC789".to_string();
        assert_eq!(
            sanitized_mac(&smashed_mac).unwrap().to_string(),
            "00:00:00:AB:C7:89".to_string()
        );
    }

    #[test]
    fn test_clean_mac() {
        let clean_mac = "DE:ED:0F:BE:EF:99".to_string();
        assert_eq!(
            sanitized_mac(&clean_mac).unwrap().to_string(),
            "DE:ED:0F:BE:EF:99".to_string()
        );
    }

    #[test]
    fn test_casey_mac() {
        let casey_mac = "AabBCcdDEefF".to_string();
        assert_eq!(
            sanitized_mac(&casey_mac).unwrap().to_string(),
            "AA:BB:CC:DD:EE:FF".to_string()
        );
    }

    #[test]
    fn test_too_long_mac() {
        let too_long_mac = "aabbccddeeffgg00112233445566778899".to_string();
        assert!(sanitized_mac(&too_long_mac).is_err());
    }

    #[test]
    fn test_deserialize_happy_mac() {
        let happy_mac = "00:11:22:33:44:55".to_string();
        let mac_address = deserialize_input_mac_to_address(&happy_mac).unwrap();
        assert_eq!(happy_mac, mac_address.to_string());
    }

    #[test]
    fn test_deserialize_ch64_mac() {
        let silly_mac = "ch:64".to_string();
        let mac_address = deserialize_input_mac_to_address(&silly_mac).unwrap();
        assert_eq!(MELLANOX_SF_VF_MAC_ADDRESS_OUT, mac_address.to_string());
    }

    #[test]
    fn test_deserialize_empty_mac() {
        let empty_mac = "".to_string();
        let mac_address = deserialize_input_mac_to_address(&empty_mac).unwrap();
        assert_eq!("00:00:00:00:00:00", mac_address.to_string());
    }
}
