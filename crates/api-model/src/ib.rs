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

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::errors::ModelError;

pub const DEFAULT_IB_FABRIC_NAME: &str = "default";

// Not implemented yet
// pub const IBNETWORK_DEFAULT_MEMBERSHIP: IBPortMembership = IBPortMembership::Full;
// pub const IBNETWORK_DEFAULT_INDEX0: bool = true;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IBNetwork {
    /// The name of IB network.
    pub name: String,
    /// The pkey of IB network.
    pub pkey: u16,
    /// Default false
    pub ipoib: bool,
    /// Quality of service parameters associated with the partition
    /// Only available if explicitly requested
    pub qos_conf: Option<IBQosConf>,
    /// Guids associated with the Partition
    /// Only available if explicitly requested
    pub associated_guids: Option<HashSet<String>>,
    /// The default membership status of ports on this partition
    /// The value is only available if all of these things are true:
    /// - The partition is the default partition
    /// - associated ports/guid are queried
    /// - UFM version is 6.19 or newer
    pub membership: Option<IBPortMembership>,
    // Not implemented yet:
    // --
    // /// Default false; create sharp allocation accordingly.
    // pub enable_sharp: bool,
    // /// The default index0 of IB network.
    // pub index0: bool,
    // --
}

/// Quality of service configuration
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IBQosConf {
    /// Default 2k; one of 2k or 4k; the MTU of the services.
    pub mtu: IBMtu,
    /// Default is None, value can be range from 0-15.
    pub service_level: IBServiceLevel,
    /// Supported values: 10, 30, 5, 20, 40, 60, 80, 120, 14, 56, 112, 168, 25, 100, 200, or 300.
    /// 2 is also valid but is used internally to represent rate limit 2.5 that is possible in UFM for lagecy hardware.
    /// It is done to avoid floating point data type usage for rate limit w/o obvious benefits.
    /// 2 to 2.5 and back conversion is done just on REST API operations.
    pub rate_limit: IBRateLimit,
}

#[derive(Clone, PartialEq, Debug)]
pub enum IBPortState {
    Active,
    Down,
    Initialize,
    Armed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IBPortMembership {
    Full,
    Limited,
}

impl std::fmt::Display for IBPortMembership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            IBPortMembership::Full => f.write_str("full"),
            IBPortMembership::Limited => f.write_str("limited"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IBPort {
    pub name: String,
    pub guid: String,
    pub lid: i32,
    /// Logical state is used.
    /// Possible states reported by device: 'Down', 'Initialize', 'Armed', 'Active'
    pub state: Option<IBPortState>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBMtu(pub i32);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBRateLimit(pub i32);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBServiceLevel(pub i32);

impl TryFrom<String> for IBPortState {
    type Error = ModelError;

    fn try_from(state: String) -> Result<Self, Self::Error> {
        match state.to_lowercase().as_str().trim() {
            "active" => Ok(IBPortState::Active),
            "down" => Ok(IBPortState::Down),
            "initialize" => Ok(IBPortState::Initialize),
            "armed" => Ok(IBPortState::Armed),
            _ => Err(ModelError::InvalidArgument(format!(
                "{state} is an invalid IBPortState"
            ))),
        }
    }
}

impl TryFrom<&str> for IBPortState {
    type Error = ModelError;

    fn try_from(state: &str) -> Result<Self, Self::Error> {
        IBPortState::try_from(state.to_string())
    }
}

impl Default for IBMtu {
    fn default() -> IBMtu {
        IBMtu(4)
    }
}

impl TryFrom<i32> for IBMtu {
    type Error = ModelError;

    fn try_from(mtu: i32) -> Result<Self, Self::Error> {
        match mtu {
            2 | 4 => Ok(Self(mtu)),
            _ => Err(ModelError::InvalidArgument(format!(
                "{mtu} is an invalid MTU"
            ))),
        }
    }
}

impl From<IBMtu> for i32 {
    fn from(mtu: IBMtu) -> i32 {
        mtu.0
    }
}

impl Default for IBRateLimit {
    fn default() -> IBRateLimit {
        IBRateLimit(200)
    }
}

impl TryFrom<i32> for IBRateLimit {
    type Error = ModelError;

    fn try_from(rate_limit: i32) -> Result<Self, Self::Error> {
        match rate_limit {
            10 | 30 | 5 | 20 | 40 | 60 | 80 | 120 | 14 | 56 | 112 | 168 | 25 | 100 | 200 | 300 => {
                Ok(Self(rate_limit))
            }
            // It is special case for SDR as 2.5
            2 => Ok(Self(rate_limit)),
            _ => Err(ModelError::InvalidArgument(format!(
                "{rate_limit} is an invalid rate limit"
            ))),
        }
    }
}

impl From<IBRateLimit> for i32 {
    fn from(rate_limit: IBRateLimit) -> i32 {
        rate_limit.0
    }
}

impl Default for IBServiceLevel {
    fn default() -> Self {
        const DEFAULT_IB_SERVICE_LEVEL: i32 = 0;
        Self(DEFAULT_IB_SERVICE_LEVEL)
    }
}

impl TryFrom<i32> for IBServiceLevel {
    type Error = ModelError;

    fn try_from(service_level: i32) -> Result<Self, Self::Error> {
        match service_level {
            0..=15 => Ok(Self(service_level)),

            _ => Err(ModelError::InvalidArgument(format!(
                "{service_level} is an invalid service level"
            ))),
        }
    }
}

impl From<IBServiceLevel> for i32 {
    fn from(service_level: IBServiceLevel) -> i32 {
        service_level.0
    }
}

#[cfg(test)]
mod tests {
    use crate::ib::IBPortMembership;

    #[test]
    fn port_membership_to_string() {
        assert_eq!(IBPortMembership::Full.to_string(), "full");
        assert_eq!(IBPortMembership::Limited.to_string(), "limited");
    }
}
