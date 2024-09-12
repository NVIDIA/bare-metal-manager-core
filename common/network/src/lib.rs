/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use mac_address::MacAddress;
use std::str::FromStr;

/// virtualization is a module specific to shared code around
/// network virtualization, where shared means shared between
/// different components, where components currently means
/// Carbide API and the [DPU] agent.
pub mod virtualization;

const STRIPPED_MAC_LENGTH: usize = 12;

/// sanitized_mac takes a potentially nasty input MAC address
/// string (e.g. `"a088c2    460c68"`, cleans up anything that
/// isn't base-16, adds colons, and returns you a nice MAC address
/// in the format of a mac_address::MacAddress.
///
///
/// For example:
///   `"a088c2    460c68"` -> `a088c2460c68` -> `A0:88:C2:46:0C:68`
///   `aa:bb:cc:DD:ee:ff`  -> `aabbccDDeeff` -> `AA:BB:CC:DD:EE:FF`
pub fn sanitized_mac(input_mac: String) -> eyre::Result<MacAddress> {
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

#[cfg(test)]
mod tests {
    use super::sanitized_mac;

    #[test]
    fn test_gross_redfish_mac() {
        let gross_redfish_mac = "\"a088c2    460c68\"".to_string();
        assert_eq!(
            sanitized_mac(gross_redfish_mac).unwrap().to_string(),
            "A0:88:C2:46:0C:68".to_string()
        );
    }

    #[test]
    fn test_smashed_mac() {
        let smashed_mac = "000000ABC789".to_string();
        assert_eq!(
            sanitized_mac(smashed_mac).unwrap().to_string(),
            "00:00:00:AB:C7:89".to_string()
        );
    }

    #[test]
    fn test_clean_mac() {
        let clean_mac = "DE:ED:0F:BE:EF:99".to_string();
        assert_eq!(
            sanitized_mac(clean_mac).unwrap().to_string(),
            "DE:ED:0F:BE:EF:99".to_string()
        );
    }

    #[test]
    fn test_casey_mac() {
        let casey_mac = "AabBCcdDEefF".to_string();
        assert_eq!(
            sanitized_mac(casey_mac).unwrap().to_string(),
            "AA:BB:CC:DD:EE:FF".to_string()
        );
    }

    #[test]
    fn test_too_long_mac() {
        let too_long_mac = "aabbccddeeffgg00112233445566778899".to_string();
        assert!(sanitized_mac(too_long_mac).is_err());
    }
}
