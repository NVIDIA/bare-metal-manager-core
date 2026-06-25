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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases};
    use model::rack_type::RackHardwareTopology;

    use super::*;

    /// Which RMS node-type resolver a table row exercises.
    #[derive(Clone, Copy, Debug)]
    enum Role {
        Compute,
        Switch,
        PowerShelf,
    }

    /// One row of the product-family x role x vendor resolution matrix: a profile
    /// built from a product family and a per-role vendor string, resolved through
    /// the `role`'s `*_for_profile` function.
    struct ResolveRow {
        product_family: Option<RackProductFamily>,
        role: Role,
        vendor: Option<&'static str>,
    }

    /// Build a profile from a row and resolve it through the row's role function.
    fn resolve(row: ResolveRow) -> Result<rms::NodeType, NodeTypeError> {
        let mut profile = RackProfile {
            product_family: row.product_family,
            ..Default::default()
        };
        let vendor = row.vendor.map(str::to_string);
        match row.role {
            Role::Compute => {
                profile.rack_capabilities.compute.vendor = vendor;
                compute_node_type_for_profile(&profile)
            }
            Role::Switch => {
                profile.rack_capabilities.switch.vendor = vendor;
                switch_node_type_for_profile(&profile)
            }
            Role::PowerShelf => {
                profile.rack_capabilities.power_shelf.vendor = vendor;
                power_shelf_node_type_for_profile(&profile)
            }
        }
    }

    /// Construct the `UnsupportedVendor` error a row is expected to fail with.
    fn unsupported(role: &'static str, vendor: &str) -> NodeTypeError {
        NodeTypeError::UnsupportedVendor {
            role,
            vendor: vendor.to_string(),
        }
    }

    fn profile_with_product_family(product_family: RackProductFamily) -> RackProfile {
        RackProfile {
            product_family: Some(product_family),
            ..Default::default()
        }
    }

    #[test]
    fn resolves_the_product_family_role_vendor_matrix() {
        use RackProductFamily::{Gb200, Gb300};

        check_cases(
            [
                // Compute: NVIDIA on every family; Lenovo only on GB300.
                Case {
                    scenario: "compute gb200 nvidia",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Compute,
                        vendor: Some("NVIDIA"),
                    },
                    expect: Yields(rms::NodeType::ComputeGb200Nvidia),
                },
                Case {
                    scenario: "compute gb300 nvidia",
                    input: ResolveRow {
                        product_family: Some(Gb300),
                        role: Role::Compute,
                        vendor: Some("NVIDIA"),
                    },
                    expect: Yields(rms::NodeType::ComputeGb300Nvidia),
                },
                Case {
                    scenario: "compute gb300 lenovo",
                    input: ResolveRow {
                        product_family: Some(Gb300),
                        role: Role::Compute,
                        vendor: Some("Lenovo"),
                    },
                    expect: Yields(rms::NodeType::ComputeGb300Lenovo),
                },
                Case {
                    scenario: "compute gb200 lenovo is unsupported (lenovo is gb300-only)",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Compute,
                        vendor: Some("Lenovo"),
                    },
                    expect: FailsWith(unsupported("compute", "Lenovo")),
                },
                Case {
                    scenario: "compute missing vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Compute,
                        vendor: None,
                    },
                    expect: FailsWith(unsupported("compute", "")),
                },
                Case {
                    scenario: "compute unsupported vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Compute,
                        vendor: Some("Other"),
                    },
                    expect: FailsWith(unsupported("compute", "Other")),
                },
                Case {
                    scenario: "compute missing product family",
                    input: ResolveRow {
                        product_family: None,
                        role: Role::Compute,
                        vendor: Some("NVIDIA"),
                    },
                    expect: FailsWith(NodeTypeError::MissingProductFamily),
                },
                // Switch: NVIDIA on every family; anything else unsupported.
                Case {
                    scenario: "switch gb200 nvidia",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Switch,
                        vendor: Some("NVIDIA"),
                    },
                    expect: Yields(rms::NodeType::SwitchGb200Nvidia),
                },
                Case {
                    scenario: "switch gb300 nvidia",
                    input: ResolveRow {
                        product_family: Some(Gb300),
                        role: Role::Switch,
                        vendor: Some("NVIDIA"),
                    },
                    expect: Yields(rms::NodeType::SwitchGb300Nvidia),
                },
                Case {
                    scenario: "switch missing vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Switch,
                        vendor: None,
                    },
                    expect: FailsWith(unsupported("switch", "")),
                },
                Case {
                    scenario: "switch unsupported vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::Switch,
                        vendor: Some("Other"),
                    },
                    expect: FailsWith(unsupported("switch", "Other")),
                },
                Case {
                    scenario: "switch missing product family",
                    input: ResolveRow {
                        product_family: None,
                        role: Role::Switch,
                        vendor: Some("NVIDIA"),
                    },
                    expect: FailsWith(NodeTypeError::MissingProductFamily),
                },
                // Power shelf: LiteOn and Delta on every family; anything else unsupported.
                Case {
                    scenario: "power shelf gb200 liteon",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::PowerShelf,
                        vendor: Some("LiteOn"),
                    },
                    expect: Yields(rms::NodeType::PowershelfGb200Liteon),
                },
                Case {
                    scenario: "power shelf gb200 delta",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::PowerShelf,
                        vendor: Some("Delta"),
                    },
                    expect: Yields(rms::NodeType::PowershelfGb200Delta),
                },
                Case {
                    scenario: "power shelf gb300 liteon",
                    input: ResolveRow {
                        product_family: Some(Gb300),
                        role: Role::PowerShelf,
                        vendor: Some("LiteOn"),
                    },
                    expect: Yields(rms::NodeType::PowershelfGb300Liteon),
                },
                Case {
                    scenario: "power shelf gb300 delta",
                    input: ResolveRow {
                        product_family: Some(Gb300),
                        role: Role::PowerShelf,
                        vendor: Some("Delta"),
                    },
                    expect: Yields(rms::NodeType::PowershelfGb300Delta),
                },
                Case {
                    scenario: "power shelf missing vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::PowerShelf,
                        vendor: None,
                    },
                    expect: FailsWith(unsupported("power shelf", "")),
                },
                Case {
                    scenario: "power shelf unsupported vendor",
                    input: ResolveRow {
                        product_family: Some(Gb200),
                        role: Role::PowerShelf,
                        vendor: Some("Other"),
                    },
                    expect: FailsWith(unsupported("power shelf", "Other")),
                },
                Case {
                    scenario: "power shelf missing product family",
                    input: ResolveRow {
                        product_family: None,
                        role: Role::PowerShelf,
                        vendor: Some("LiteOn"),
                    },
                    expect: FailsWith(NodeTypeError::MissingProductFamily),
                },
            ],
            resolve,
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
    fn product_family_not_topology_selects_node_type() {
        let mut profile = profile_with_product_family(RackProductFamily::Gb300);
        profile.rack_hardware_topology = Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology);
        profile.rack_capabilities.switch.vendor = Some("NVIDIA".to_string());

        let node_type = switch_node_type_for_profile(&profile);

        assert_eq!(node_type, Ok(rms::NodeType::SwitchGb300Nvidia));
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
