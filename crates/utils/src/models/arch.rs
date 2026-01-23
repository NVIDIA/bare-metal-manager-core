/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::str::FromStr;

#[derive(Debug)]
pub struct UnsupportedCpuArchitecture(pub String);

impl std::error::Error for UnsupportedCpuArchitecture {}

impl std::fmt::Display for UnsupportedCpuArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "CPU architecture '{}' is not supported", self.0)
    }
}

#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CpuArchitecture {
    Aarch64,
    X86_64,
    // For predicated hosts we don't know yet
    #[default]
    #[serde(rename = "")]
    Unknown,
}

impl std::fmt::Display for CpuArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use CpuArchitecture::*;
        let s = match self {
            Aarch64 => "aarch64",
            X86_64 => "x86_64",
            _ => "",
        };
        write!(f, "{s}")
    }
}

impl FromStr for CpuArchitecture {
    type Err = UnsupportedCpuArchitecture;

    // Convert from `uname` output
    // Not used to convert from DB or JSON. That's the derived serde::Deserialize.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arch = match s {
            "aarch64" => Ok(CpuArchitecture::Aarch64),
            "x86_64" => Ok(CpuArchitecture::X86_64),
            "" => Ok(CpuArchitecture::Unknown), // Predicted hosts
            _ => Err(UnsupportedCpuArchitecture(s.to_string())),
        }?;
        Ok(arch)
    }
}

impl From<CpuArchitecture> for i32 {
    fn from(a: CpuArchitecture) -> Self {
        match a {
            CpuArchitecture::Aarch64 => rpc::machine_discovery::CpuArchitecture::Aarch64 as i32,
            CpuArchitecture::X86_64 => rpc::machine_discovery::CpuArchitecture::X8664 as i32,
            CpuArchitecture::Unknown => rpc::machine_discovery::CpuArchitecture::Unknown as i32,
        }
    }
}

impl From<i32> for CpuArchitecture {
    fn from(a: i32) -> Self {
        match rpc::machine_discovery::CpuArchitecture::try_from(a) {
            Ok(rpc::machine_discovery::CpuArchitecture::Aarch64) => CpuArchitecture::Aarch64,
            Ok(rpc::machine_discovery::CpuArchitecture::X8664) => CpuArchitecture::X86_64,
            _ => CpuArchitecture::Unknown,
        }
    }
}
