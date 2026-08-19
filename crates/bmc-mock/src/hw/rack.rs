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

use crate::HardwareType;

const FIRST_COMPUTE_RANGE_START: u8 = 11;
const FIRST_COMPUTE_RANGE_END: u8 = 18;
const SECOND_COMPUTE_RANGE_START: u8 = 28;
const SECOND_COMPUTE_RANGE_END: u8 = 37;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RackPlacement {
    position: u8,
    topology_id: u32,
}

impl RackPlacement {
    pub(crate) fn new(position: u8, topology_id: u32) -> Self {
        Self {
            position,
            topology_id,
        }
    }

    pub fn position(self) -> u8 {
        self.position
    }

    pub fn topology_id(self) -> u32 {
        self.topology_id
    }

    pub(crate) fn compute_tray_index(self) -> Option<u8> {
        match self.position {
            FIRST_COMPUTE_RANGE_START..=FIRST_COMPUTE_RANGE_END => {
                Some(self.position - FIRST_COMPUTE_RANGE_START)
            }
            SECOND_COMPUTE_RANGE_START..=SECOND_COMPUTE_RANGE_END => {
                Some(self.position - SECOND_COMPUTE_RANGE_START + 8)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RackUnit {
    pub position: u8,
    pub hardware_type: HardwareType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RackElevation {
    pub version: u32,
    pub units: Vec<RackUnit>,
}
