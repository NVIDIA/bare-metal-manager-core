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

use libredfish::model::service_root::RedfishVendor;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    clap::ValueEnum,
    clap::Parser,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum BMCVendor {
    Lenovo,
    Dell,
    Supermicro,
    Hpe,
    Nvidia, // DPU, Viking, Oberon
    Liteon,
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
            "dell" => BMCVendor::Dell,
            "supermicro" => BMCVendor::Supermicro,
            "hpe" => BMCVendor::Hpe,
            "nvidia" => BMCVendor::Nvidia,
            "liteon" => BMCVendor::Liteon,
            _ => BMCVendor::Unknown,
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
            BMCVendor::Dell => "Dell",
            BMCVendor::Supermicro => "Supermicro",
            BMCVendor::Hpe => "Hpe",
            BMCVendor::Nvidia => "Nvidia",
            BMCVendor::Liteon => "Liteon",
            BMCVendor::Unknown => "Unknown",
        }
        .to_string()
    }
    pub fn is_lenovo(&self) -> bool {
        *self == Self::Lenovo
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

    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}

impl From<RedfishVendor> for BMCVendor {
    fn from(r: RedfishVendor) -> BMCVendor {
        match r {
            RedfishVendor::AMI
            | RedfishVendor::NvidiaDpu
            | RedfishVendor::NvidiaGBx00
            | RedfishVendor::NvidiaGH200
            | RedfishVendor::NvidiaGBSwitch
            | RedfishVendor::P3809 => BMCVendor::Nvidia,
            RedfishVendor::Dell => BMCVendor::Dell,
            RedfishVendor::Hpe => BMCVendor::Hpe,
            RedfishVendor::Lenovo => BMCVendor::Lenovo,
            RedfishVendor::LiteOnPowerShelf => BMCVendor::Liteon,
            RedfishVendor::Supermicro => BMCVendor::Supermicro,
            RedfishVendor::Unknown => BMCVendor::Unknown,
        }
    }
}
