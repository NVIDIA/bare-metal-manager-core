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

use librms::protos::rack_manager as rms;
use model::rack_type::{RackProductFamily, RackProfile};

/// Power shelf vendors represented by RMS node type variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowerShelfVendor {
    /// LiteOn power shelf hardware.
    Liteon,
    /// Delta power shelf hardware.
    Delta,
}

/// Error returned when local data cannot resolve an RMS node type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeTypeError {
    /// The rack profile does not identify a product family needed by RMS.
    #[error("rack profile does not identify an RMS product family")]
    MissingProductFamily,
    /// The configured vendor is not supported for the node role.
    #[error("RMS does not support {role} vendor {vendor}")]
    UnsupportedVendor { role: &'static str, vendor: String },
}

/// Resolves the RMS compute node type for a rack profile.
pub fn compute_node_type_for_profile(
    profile: &RackProfile,
) -> Result<rms::NodeType, NodeTypeError> {
    let product_family = profile
        .product_family
        .ok_or(NodeTypeError::MissingProductFamily)?;
    let vendor = profile
        .rack_capabilities
        .compute
        .vendor
        .as_deref()
        .map(str::trim)
        .filter(|vendor| !vendor.is_empty());

    compute_node_type(product_family, vendor)
}

/// Resolves the RMS switch node type for a rack profile.
pub fn switch_node_type_for_profile(profile: &RackProfile) -> Result<rms::NodeType, NodeTypeError> {
    let product_family = profile
        .product_family
        .ok_or(NodeTypeError::MissingProductFamily)?;
    let vendor = profile
        .rack_capabilities
        .switch
        .vendor
        .as_deref()
        .map(str::trim)
        .filter(|vendor| !vendor.is_empty());

    let Some(vendor) = vendor else {
        return Err(NodeTypeError::UnsupportedVendor {
            role: "switch",
            vendor: String::new(),
        });
    };

    if !is_vendor(vendor, "nvidia") {
        return Err(NodeTypeError::UnsupportedVendor {
            role: "switch",
            vendor: vendor.to_string(),
        });
    }

    Ok(switch_node_type(product_family))
}

/// Resolves the RMS power shelf node type for a rack profile.
pub fn power_shelf_node_type_for_profile(
    profile: &RackProfile,
) -> Result<rms::NodeType, NodeTypeError> {
    let product_family = profile
        .product_family
        .ok_or(NodeTypeError::MissingProductFamily)?;
    let vendor = profile
        .rack_capabilities
        .power_shelf
        .vendor
        .as_deref()
        .map(str::trim)
        .filter(|vendor| !vendor.is_empty());

    let Some(vendor) = vendor else {
        return Err(NodeTypeError::UnsupportedVendor {
            role: "power shelf",
            vendor: String::new(),
        });
    };

    let Some(power_shelf_vendor) = supported_power_shelf_vendor(vendor) else {
        return Err(NodeTypeError::UnsupportedVendor {
            role: "power shelf",
            vendor: vendor.to_string(),
        });
    };

    Ok(power_shelf_node_type(product_family, power_shelf_vendor))
}

/// Returns true when an RMS node type represents a switch.
pub(crate) fn is_switch_node_type(node_type: rms::NodeType) -> bool {
    // Keep this exhaustive so new RMS node types must be classified when
    // librms adds variants.
    match node_type {
        rms::NodeType::SwitchGb200Nvidia | rms::NodeType::SwitchGb300Nvidia => true,
        rms::NodeType::Unspecified
        | rms::NodeType::ComputeGb200Nvidia
        | rms::NodeType::PowershelfGb200Liteon
        | rms::NodeType::PowershelfGb200Delta
        | rms::NodeType::ComputeGb300Nvidia
        | rms::NodeType::PowershelfGb300Liteon
        | rms::NodeType::PowershelfGb300Delta
        | rms::NodeType::ComputeGb300Lenovo => false,
    }
}

fn compute_node_type(
    product_family: RackProductFamily,
    vendor: Option<&str>,
) -> Result<rms::NodeType, NodeTypeError> {
    let nvidia_node_type = match product_family {
        RackProductFamily::Gb200 => rms::NodeType::ComputeGb200Nvidia,
        RackProductFamily::Gb300 => rms::NodeType::ComputeGb300Nvidia,
    };

    let Some(vendor) = vendor else {
        return Err(NodeTypeError::UnsupportedVendor {
            role: "compute",
            vendor: String::new(),
        });
    };

    if is_vendor(vendor, "nvidia") {
        return Ok(nvidia_node_type);
    }

    if matches!(product_family, RackProductFamily::Gb300) && is_vendor(vendor, "lenovo") {
        return Ok(rms::NodeType::ComputeGb300Lenovo);
    }

    Err(NodeTypeError::UnsupportedVendor {
        role: "compute",
        vendor: vendor.to_string(),
    })
}

fn switch_node_type(product_family: RackProductFamily) -> rms::NodeType {
    match product_family {
        RackProductFamily::Gb200 => rms::NodeType::SwitchGb200Nvidia,
        RackProductFamily::Gb300 => rms::NodeType::SwitchGb300Nvidia,
    }
}

fn power_shelf_node_type(
    product_family: RackProductFamily,
    vendor: PowerShelfVendor,
) -> rms::NodeType {
    match (product_family, vendor) {
        (RackProductFamily::Gb200, PowerShelfVendor::Liteon) => {
            rms::NodeType::PowershelfGb200Liteon
        }
        (RackProductFamily::Gb200, PowerShelfVendor::Delta) => rms::NodeType::PowershelfGb200Delta,
        (RackProductFamily::Gb300, PowerShelfVendor::Liteon) => {
            rms::NodeType::PowershelfGb300Liteon
        }
        (RackProductFamily::Gb300, PowerShelfVendor::Delta) => rms::NodeType::PowershelfGb300Delta,
    }
}

fn supported_power_shelf_vendor(vendor: &str) -> Option<PowerShelfVendor> {
    if is_vendor(vendor, "liteon") {
        Some(PowerShelfVendor::Liteon)
    } else if is_vendor(vendor, "delta") {
        Some(PowerShelfVendor::Delta)
    } else {
        None
    }
}

fn is_vendor(vendor: &str, expected: &str) -> bool {
    // Vendors often include spaces, punctuation, or company suffixes. Match at
    // the front after compacting those differences so embedded names do not
    // classify unrelated vendors as supported.
    normalize(vendor).starts_with(&normalize(expected))
}

fn normalize(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "")
}

#[cfg(test)]
mod tests {
    use model::rack_type::RackHardwareTopology;

    use super::*;

    fn profile_with_product_family(product_family: RackProductFamily) -> RackProfile {
        RackProfile {
            product_family: Some(product_family),
            ..Default::default()
        }
    }

    #[test]
    fn compute_node_type_maps_gb200_nvidia() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb200);
        profile.rack_capabilities.compute.vendor = Some("NVIDIA".to_string());

        let node_type = compute_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::ComputeGb200Nvidia));
    }

    #[test]
    fn compute_node_type_maps_gb300_nvidia() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb300);
        profile.rack_capabilities.compute.vendor = Some("NVIDIA".to_string());

        let node_type = compute_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::ComputeGb300Nvidia));
    }

    #[test]
    fn compute_node_type_maps_gb300_lenovo() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb300);
        profile.rack_capabilities.compute.vendor = Some("Lenovo".to_string());

        let node_type = compute_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::ComputeGb300Lenovo));
    }

    #[test]
    fn switch_node_type_maps_gb200_and_gb300() {
        let mut gb200 = profile_with_product_family(RackProductFamily::Gb200);
        gb200.rack_capabilities.switch.vendor = Some("NVIDIA".to_string());

        let mut gb300 = profile_with_product_family(RackProductFamily::Gb300);
        gb300.rack_capabilities.switch.vendor = Some("NVIDIA".to_string());

        assert_eq!(
            switch_node_type_for_profile(&gb200),
            Ok(rms::NodeType::SwitchGb200Nvidia)
        );
        assert_eq!(
            switch_node_type_for_profile(&gb300),
            Ok(rms::NodeType::SwitchGb300Nvidia)
        );
    }

    #[test]
    fn switch_node_type_requires_vendor() {
        let profile = profile_with_product_family(RackProductFamily::Gb200);

        let node_type = switch_node_type_for_profile(&profile);

        assert_eq!(
            node_type,
            Err(NodeTypeError::UnsupportedVendor {
                role: "switch",
                vendor: String::new()
            })
        );
    }

    #[test]
    fn switch_node_type_uses_profile_vendor_for_validation() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb200);
        profile.rack_capabilities.switch.vendor = Some("Other".to_string());

        let node_type = switch_node_type_for_profile(&profile);

        assert_eq!(
            node_type,
            Err(NodeTypeError::UnsupportedVendor {
                role: "switch",
                vendor: "Other".to_string()
            })
        );
    }

    #[test]
    fn is_switch_node_type_matches_switch_variants_only() {
        let switch_types = [
            rms::NodeType::SwitchGb200Nvidia,
            rms::NodeType::SwitchGb300Nvidia,
        ];

        for node_type in switch_types {
            assert!(is_switch_node_type(node_type));
        }

        let non_switch_types = [
            rms::NodeType::Unspecified,
            rms::NodeType::ComputeGb200Nvidia,
            rms::NodeType::PowershelfGb200Liteon,
            rms::NodeType::PowershelfGb200Delta,
            rms::NodeType::ComputeGb300Nvidia,
            rms::NodeType::PowershelfGb300Liteon,
            rms::NodeType::PowershelfGb300Delta,
            rms::NodeType::ComputeGb300Lenovo,
        ];

        for node_type in non_switch_types {
            assert!(!is_switch_node_type(node_type));
        }
    }

    #[test]
    fn power_shelf_node_type_uses_profile_vendor() {
        let mut gb200_liteon = profile_with_product_family(RackProductFamily::Gb200);
        gb200_liteon.rack_capabilities.power_shelf.vendor = Some("LiteOn".to_string());

        let mut gb300_delta = profile_with_product_family(RackProductFamily::Gb300);
        gb300_delta.rack_capabilities.power_shelf.vendor = Some("Delta".to_string());

        assert_eq!(
            power_shelf_node_type_for_profile(&gb200_liteon),
            Ok(rms::NodeType::PowershelfGb200Liteon)
        );

        assert_eq!(
            power_shelf_node_type_for_profile(&gb300_delta),
            Ok(rms::NodeType::PowershelfGb300Delta)
        );
    }

    #[test]
    fn power_shelf_node_type_requires_supported_vendor() {
        let profile = profile_with_product_family(RackProductFamily::Gb200);

        assert_eq!(
            power_shelf_node_type_for_profile(&profile),
            Err(NodeTypeError::UnsupportedVendor {
                role: "power shelf",
                vendor: String::new()
            })
        );
    }

    #[test]
    fn product_family_not_topology_selects_node_type() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb300);
        profile.rack_hardware_topology = Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology);
        profile.rack_capabilities.switch.vendor = Some("NVIDIA".to_string());

        let node_type = switch_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::SwitchGb300Nvidia));
    }

    #[test]
    fn compute_node_type_requires_vendor() {
        let profile = profile_with_product_family(RackProductFamily::Gb200);

        let err = compute_node_type_for_profile(&profile);

        assert_eq!(
            err,
            Err(NodeTypeError::UnsupportedVendor {
                role: "compute",
                vendor: String::new()
            })
        );
    }

    #[test]
    fn compute_node_type_requires_product_family() {
        let mut profile = RackProfile::default();
        profile.rack_capabilities.compute.vendor = Some("NVIDIA".to_string());

        let err = compute_node_type_for_profile(&profile);

        assert_eq!(err, Err(NodeTypeError::MissingProductFamily));
    }

    #[test]
    fn unsupported_vendor_returns_error() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb200);
        profile.rack_capabilities.compute.vendor = Some("Other".to_string());

        let err = compute_node_type_for_profile(&profile);

        assert_eq!(
            err,
            Err(NodeTypeError::UnsupportedVendor {
                role: "compute",
                vendor: "Other".to_string()
            })
        );
    }

    #[test]
    fn vendor_matching_trims_outer_whitespace() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb200);
        profile.rack_capabilities.compute.vendor = Some("\tNVIDIA\n".to_string());

        let node_type = compute_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::ComputeGb200Nvidia));
    }

    #[test]
    fn embedded_vendor_name_does_not_match() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb200);
        profile.rack_capabilities.compute.vendor = Some("Not NVIDIA".to_string());

        let err = compute_node_type_for_profile(&profile);

        assert_eq!(
            err,
            Err(NodeTypeError::UnsupportedVendor {
                role: "compute",
                vendor: "Not NVIDIA".to_string()
            })
        );
    }
}
