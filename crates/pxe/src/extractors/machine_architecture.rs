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

use nico_rpc::forge;
use serde::{Deserialize, Serialize};

use crate::rpc_error::PxeRequestError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MachineArchitecture {
    Arm = 0,
    X86 = 1,
}

impl TryFrom<&str> for MachineArchitecture {
    type Error = PxeRequestError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "arm64" => Ok(MachineArchitecture::Arm),
            "x86_64" => Ok(MachineArchitecture::X86),
            x if x == (MachineArchitecture::Arm as u64).to_string().as_str() => {
                Ok(MachineArchitecture::Arm)
            }
            x if x == (MachineArchitecture::X86 as u64).to_string().as_str() => {
                Ok(MachineArchitecture::X86)
            }
            _ => Err(PxeRequestError::MalformedBuildArch(format!(
                "Not a valid architecture identifier: {value}"
            ))),
        }
    }
}

impl From<MachineArchitecture> for forge::MachineArchitecture {
    fn from(arch: MachineArchitecture) -> forge::MachineArchitecture {
        match arch {
            MachineArchitecture::X86 => forge::MachineArchitecture::X86,
            MachineArchitecture::Arm => forge::MachineArchitecture::Arm,
        }
    }
}
