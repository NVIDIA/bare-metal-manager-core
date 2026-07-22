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

//! BMC Manufacturer ID

use std::fmt;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Hash,
    Eq,
    PartialEq,
    clap::ValueEnum,
    clap::Parser,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum BMCVendor {
    Lenovo,
    LenovoAMI,
    Dell,
    Supermicro,
    Hpe,
    Nvidia, // DPU, Viking, Oberon
    Liteon,
    Delta,
    #[serde(other)]
    #[default]
    Unknown,
}

impl fmt::Display for BMCVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{self:?}").to_lowercase();
        write!(f, "{s}")
    }
}

impl From<&str> for BMCVendor {
    fn from(s: &str) -> BMCVendor {
        match s.to_lowercase().as_str() {
            "lenovo" => BMCVendor::Lenovo,
            "lenovoami" => BMCVendor::LenovoAMI,
            "dell" => BMCVendor::Dell,
            "supermicro" => BMCVendor::Supermicro,
            "hpe" => BMCVendor::Hpe,
            "nvidia" => BMCVendor::Nvidia,
            "liteon" => BMCVendor::Liteon,
            "delta" => BMCVendor::Delta,
            _ => BMCVendor::Unknown,
        }
    }
}

/// DPU generation / model identifier used to key per-model factory default credentials.
///
/// The `Display` impl produces the lowercase vault path segment ("bf3", "bf4", ...).
/// `Unknown` maps to "unknown" for new vault paths; existing deployments keep their
/// legacy entry at `machines/all_dpus/factory_default/bmc-metadata-items/root`, which
/// the credential key encoding maps `Unknown` to for backward compatibility.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Hash,
    Eq,
    PartialEq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum DpuModel {
    #[value(name = "bf2")]
    BlueField2,
    #[value(name = "bf3")]
    BlueField3,
    #[value(name = "bf4")]
    BlueField4,
    #[serde(other)]
    #[default]
    Unknown,
}

impl fmt::Display for DpuModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DpuModel::BlueField2 => "bf2",
            DpuModel::BlueField3 => "bf3",
            DpuModel::BlueField4 => "bf4",
            DpuModel::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

impl From<&str> for DpuModel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bf2" => DpuModel::BlueField2,
            "bf3" => DpuModel::BlueField3,
            "bf4" => DpuModel::BlueField4,
            _ => DpuModel::Unknown,
        }
    }
}

impl DpuModel {
    /// Identify the DPU generation from the Redfish service root `Product` field,
    /// which BlueField BMCs set to a human-readable model string (e.g. "BlueField-3 DPU").
    /// Returns `Unknown` for unrecognized strings so callers can fall back gracefully.
    pub fn from_service_root_product(product: &str) -> Self {
        let lower = product.to_lowercase();
        if lower.contains("bluefield-2") || lower.contains("bluefield 2") {
            DpuModel::BlueField2
        } else if lower.contains("bluefield-3") || lower.contains("bluefield 3") {
            DpuModel::BlueField3
        } else if lower.contains("bluefield-4") || lower.contains("bluefield 4") {
            DpuModel::BlueField4
        } else {
            DpuModel::Unknown
        }
    }

    /// Publicly-documented factory-default BMC credentials `(username, password)`
    /// for this DPU generation.
    ///
    /// This is the single source of truth shared by site-explorer's last-resort
    /// credential fallback (used when no vault entry is configured) and the BMC
    /// mock's factory-default account, so the two cannot drift. BlueField-4 ships
    /// with a distinct default account (`admin`); earlier generations and
    /// unrecognized models use the legacy `root` default.
    pub fn default_factory_credentials(&self) -> (&'static str, &'static str) {
        match self {
            DpuModel::BlueField4 => ("admin", "0penBmc"),
            DpuModel::BlueField2 | DpuModel::BlueField3 | DpuModel::Unknown => ("root", "0penBmc"),
        }
    }
}

impl BMCVendor {
    /// From the string libudev returns querying the dmi subsystem
    pub fn from_udev_dmi(s: &str) -> BMCVendor {
        match s {
            "Lenovo" => BMCVendor::Lenovo,
            "Dell Inc." => BMCVendor::Dell,
            "https://www.mellanox.com" => BMCVendor::Nvidia,
            "NVIDIA" => BMCVendor::Nvidia,
            "Supermicro" => BMCVendor::Supermicro,
            "HPE" => BMCVendor::Hpe,
            _ => BMCVendor::Unknown,
        }
    }

    /// BMC vendors issue their own TLS certs. Match on the Organization in that cert.
    pub fn from_tls_issuer(s: &str) -> BMCVendor {
        match s {
            "Lenovo" => BMCVendor::Lenovo,
            "Dell Inc." => BMCVendor::Dell,
            "Super Micro Computer" => BMCVendor::Supermicro,
            "Hewlett Packard Enterprise" => BMCVendor::Hpe,
            "American Megatrends International LLC (AMI)" => BMCVendor::Nvidia,
            "OpenBMC" => BMCVendor::Nvidia,
            _ => BMCVendor::Unknown,
        }
    }

    /// to_pascalcase converts to StringLikeThis to match serialization
    pub fn to_pascalcase(self) -> String {
        match self {
            BMCVendor::Lenovo => "Lenovo",
            BMCVendor::LenovoAMI => "LenovoAMI",
            BMCVendor::Dell => "Dell",
            BMCVendor::Supermicro => "Supermicro",
            BMCVendor::Hpe => "Hpe",
            BMCVendor::Nvidia => "Nvidia",
            BMCVendor::Liteon => "Liteon",
            BMCVendor::Delta => "Delta",
            BMCVendor::Unknown => "Unknown",
        }
        .to_string()
    }
    pub fn is_lenovo(&self) -> bool {
        *self == Self::Lenovo
    }

    pub fn is_lenovo_ami(&self) -> bool {
        *self == Self::LenovoAMI
    }

    pub fn is_supermicro(&self) -> bool {
        *self == Self::Supermicro
    }

    pub fn is_nvidia(&self) -> bool {
        *self == Self::Nvidia
    }

    pub fn is_dell(&self) -> bool {
        *self == Self::Dell
    }

    pub fn is_hpe(&self) -> bool {
        *self == Self::Hpe
    }

    pub fn is_liteon(&self) -> bool {
        *self == Self::Liteon
    }

    pub fn is_delta(&self) -> bool {
        *self == Self::Delta
    }

    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}
