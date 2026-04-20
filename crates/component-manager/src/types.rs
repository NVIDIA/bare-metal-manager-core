// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use mac_address::MacAddress;

use crate::error::ComponentManagerError;

pub fn parse_mac(s: &str) -> Result<MacAddress, ComponentManagerError> {
    s.parse::<MacAddress>()
        .map_err(|e| ComponentManagerError::Internal(format!("invalid MAC from backend: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::power_shelf_manager::PowerShelfVendor;

    #[test]
    fn parse_mac_valid_colon_separated() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac.to_string(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn parse_mac_valid_lowercase() {
        assert!(parse_mac("aa:bb:cc:dd:ee:ff").is_ok());
    }

    #[test]
    fn parse_mac_invalid_string() {
        let err = parse_mac("not-a-mac").unwrap_err();
        assert!(matches!(err, ComponentManagerError::Internal(msg) if msg.contains("invalid MAC")));
    }

    #[test]
    fn parse_mac_empty_string() {
        assert!(parse_mac("").is_err());
    }

    #[test]
    fn parse_mac_too_short() {
        assert!(parse_mac("AA:BB:CC").is_err());
    }

    #[test]
    fn power_shelf_vendor_default_is_liteon() {
        assert_eq!(PowerShelfVendor::DEFAULT, PowerShelfVendor::Liteon);
    }
}
