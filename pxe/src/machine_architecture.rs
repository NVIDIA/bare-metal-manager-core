/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use ::rpc::forge as rpc;

#[derive(Debug, Clone)]
pub enum MachineArchitecture {
    Arm,
    X86,
}

impl From<MachineArchitecture> for rpc::MachineArchitecture {
    fn from(arch: MachineArchitecture) -> rpc::MachineArchitecture {
        match arch {
            MachineArchitecture::X86 => rpc::MachineArchitecture::X86,
            MachineArchitecture::Arm => rpc::MachineArchitecture::Arm,
        }
    }
}

impl From<rpc::MachineArchitecture> for MachineArchitecture {
    fn from(arch: rpc::MachineArchitecture) -> Self {
        match arch {
            rpc::MachineArchitecture::X86 => MachineArchitecture::X86,
            rpc::MachineArchitecture::Arm => MachineArchitecture::Arm,
        }
    }
}

impl FromStr for MachineArchitecture {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "arm64" => Ok(Self::Arm),
            "x86_64" => Ok(Self::X86),
            _ => Err(()),
        }
    }
}
impl Display for MachineArchitecture {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::X86 => "x86_64",
                Self::Arm => "arm64",
            }
        )
    }
}

impl MachineArchitecture {}
