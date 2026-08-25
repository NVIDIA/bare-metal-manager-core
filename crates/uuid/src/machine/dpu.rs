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

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use super::{InvalidMachineType, MachineId, MachineType};

/// A machine ID that identifies a DPU.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct DpuMachineId(pub(super) MachineId);

impl DpuMachineId {
    /// Returns the underlying machine ID.
    pub fn as_machine_id(&self) -> &MachineId {
        &self.0
    }
}

impl AsRef<MachineId> for DpuMachineId {
    fn as_ref(&self) -> &MachineId {
        &self.0
    }
}

impl TryFrom<MachineId> for DpuMachineId {
    type Error = InvalidMachineType;

    fn try_from(id: MachineId) -> Result<Self, Self::Error> {
        match id.machine_type() {
            MachineType::Dpu => Ok(Self(id)),
            _ => Err(InvalidMachineType {
                expected: "DPU machine ID",
                actual: id,
            }),
        }
    }
}

impl FromStr for DpuMachineId {
    type Err = crate::machine::MachineIdSubtypeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = MachineId::from_str(value)?;
        Ok(Self::try_from(id)?)
    }
}

impl From<DpuMachineId> for MachineId {
    fn from(id: DpuMachineId) -> Self {
        id.0
    }
}

impl Display for DpuMachineId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<'de> serde::Deserialize<'de> for DpuMachineId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <MachineId as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from(id).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "sqlx")]
impl_sqlx_for_machine_id_newtype!(DpuMachineId);
