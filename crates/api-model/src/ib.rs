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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use crate::ib::{IBMtu, IBPortMembership, IBPortState, IBRateLimit, IBServiceLevel};

    #[test]
    fn port_membership_to_string() {
        check_values(
            [
                Check {
                    scenario: "full",
                    input: IBPortMembership::Full,
                    expect: "full".to_string(),
                },
                Check {
                    scenario: "limited",
                    input: IBPortMembership::Limited,
                    expect: "limited".to_string(),
                },
            ],
            |membership| membership.to_string(),
        );
    }

    #[test]
    fn port_state_try_from_str() {
        check_cases(
            [
                Case {
                    scenario: "active",
                    input: "active",
                    expect: Yields(IBPortState::Active),
                },
                Case {
                    scenario: "down",
                    input: "down",
                    expect: Yields(IBPortState::Down),
                },
                Case {
                    scenario: "initialize",
                    input: "initialize",
                    expect: Yields(IBPortState::Initialize),
                },
                Case {
                    scenario: "armed",
                    input: "armed",
                    expect: Yields(IBPortState::Armed),
                },
                Case {
                    scenario: "uppercase is lowercased",
                    input: "ACTIVE",
                    expect: Yields(IBPortState::Active),
                },
                Case {
                    scenario: "mixed case",
                    input: "ArMeD",
                    expect: Yields(IBPortState::Armed),
                },
                Case {
                    scenario: "surrounding whitespace is trimmed",
                    input: "  down  ",
                    expect: Yields(IBPortState::Down),
                },
                Case {
                    scenario: "empty string",
                    input: "",
                    expect: Fails,
                },
                Case {
                    scenario: "whitespace only",
                    input: "   ",
                    expect: Fails,
                },
                Case {
                    scenario: "unknown word",
                    input: "sleeping",
                    expect: Fails,
                },
                Case {
                    scenario: "near miss",
                    input: "actives",
                    expect: Fails,
                },
            ],
            |state| IBPortState::try_from(state).map_err(drop),
        );
    }

    #[test]
    fn port_state_try_from_string() {
        check_cases(
            [
                Case {
                    scenario: "active",
                    input: "active".to_string(),
                    expect: Yields(IBPortState::Active),
                },
                Case {
                    scenario: "trimmed and lowercased",
                    input: " Initialize ".to_string(),
                    expect: Yields(IBPortState::Initialize),
                },
                Case {
                    scenario: "invalid",
                    input: "bogus".to_string(),
                    expect: Fails,
                },
            ],
            |state| IBPortState::try_from(state).map_err(drop),
        );
    }

    #[test]
    fn mtu_default_is_4() {
        Check {
            scenario: "default mtu",
            input: (),
            expect: IBMtu(4),
        }
        .check(|()| IBMtu::default());
    }

    #[test]
    fn mtu_try_from_i32() {
        check_cases(
            [
                Case {
                    scenario: "2k",
                    input: 2,
                    expect: Yields(IBMtu(2)),
                },
                Case {
                    scenario: "4k",
                    input: 4,
                    expect: Yields(IBMtu(4)),
                },
                Case {
                    scenario: "zero",
                    input: 0,
                    expect: Fails,
                },
                Case {
                    scenario: "one",
                    input: 1,
                    expect: Fails,
                },
                Case {
                    scenario: "three between valid values",
                    input: 3,
                    expect: Fails,
                },
                Case {
                    scenario: "negative",
                    input: -2,
                    expect: Fails,
                },
                Case {
                    scenario: "large",
                    input: 4096,
                    expect: Fails,
                },
            ],
            |mtu| IBMtu::try_from(mtu).map_err(drop),
        );
    }

    #[test]
    fn mtu_into_i32() {
        check_values(
            [
                Check {
                    scenario: "2k",
                    input: IBMtu(2),
                    expect: 2,
                },
                Check {
                    scenario: "4k",
                    input: IBMtu(4),
                    expect: 4,
                },
            ],
            i32::from,
        );
    }

    #[test]
    fn rate_limit_default_is_200() {
        Check {
            scenario: "default rate limit",
            input: (),
            expect: IBRateLimit(200),
        }
        .check(|()| IBRateLimit::default());
    }

    #[test]
    fn rate_limit_try_from_i32() {
        check_cases(
            [
                Case {
                    scenario: "legacy sdr 2.5 sentinel",
                    input: 2,
                    expect: Yields(IBRateLimit(2)),
                },
                Case {
                    scenario: "5",
                    input: 5,
                    expect: Yields(IBRateLimit(5)),
                },
                Case {
                    scenario: "10",
                    input: 10,
                    expect: Yields(IBRateLimit(10)),
                },
                Case {
                    scenario: "14",
                    input: 14,
                    expect: Yields(IBRateLimit(14)),
                },
                Case {
                    scenario: "20",
                    input: 20,
                    expect: Yields(IBRateLimit(20)),
                },
                Case {
                    scenario: "25",
                    input: 25,
                    expect: Yields(IBRateLimit(25)),
                },
                Case {
                    scenario: "30",
                    input: 30,
                    expect: Yields(IBRateLimit(30)),
                },
                Case {
                    scenario: "40",
                    input: 40,
                    expect: Yields(IBRateLimit(40)),
                },
                Case {
                    scenario: "56",
                    input: 56,
                    expect: Yields(IBRateLimit(56)),
                },
                Case {
                    scenario: "60",
                    input: 60,
                    expect: Yields(IBRateLimit(60)),
                },
                Case {
                    scenario: "80",
                    input: 80,
                    expect: Yields(IBRateLimit(80)),
                },
                Case {
                    scenario: "100",
                    input: 100,
                    expect: Yields(IBRateLimit(100)),
                },
                Case {
                    scenario: "112",
                    input: 112,
                    expect: Yields(IBRateLimit(112)),
                },
                Case {
                    scenario: "120",
                    input: 120,
                    expect: Yields(IBRateLimit(120)),
                },
                Case {
                    scenario: "168",
                    input: 168,
                    expect: Yields(IBRateLimit(168)),
                },
                Case {
                    scenario: "200",
                    input: 200,
                    expect: Yields(IBRateLimit(200)),
                },
                Case {
                    scenario: "300",
                    input: 300,
                    expect: Yields(IBRateLimit(300)),
                },
                Case {
                    scenario: "zero",
                    input: 0,
                    expect: Fails,
                },
                Case {
                    scenario: "one",
                    input: 1,
                    expect: Fails,
                },
                Case {
                    scenario: "three is not a valid rate",
                    input: 3,
                    expect: Fails,
                },
                Case {
                    scenario: "negative",
                    input: -200,
                    expect: Fails,
                },
                Case {
                    scenario: "unsupported large",
                    input: 400,
                    expect: Fails,
                },
            ],
            |rate| IBRateLimit::try_from(rate).map_err(drop),
        );
    }

    #[test]
    fn rate_limit_into_i32() {
        check_values(
            [
                Check {
                    scenario: "200",
                    input: IBRateLimit(200),
                    expect: 200,
                },
                Check {
                    scenario: "sdr sentinel",
                    input: IBRateLimit(2),
                    expect: 2,
                },
            ],
            i32::from,
        );
    }

    #[test]
    fn service_level_default_is_0() {
        Check {
            scenario: "default service level",
            input: (),
            expect: IBServiceLevel(0),
        }
        .check(|()| IBServiceLevel::default());
    }

    #[test]
    fn service_level_try_from_i32() {
        check_cases(
            [
                Case {
                    scenario: "lower bound 0",
                    input: 0,
                    expect: Yields(IBServiceLevel(0)),
                },
                Case {
                    scenario: "mid 7",
                    input: 7,
                    expect: Yields(IBServiceLevel(7)),
                },
                Case {
                    scenario: "upper bound 15",
                    input: 15,
                    expect: Yields(IBServiceLevel(15)),
                },
                Case {
                    scenario: "just past upper bound",
                    input: 16,
                    expect: Fails,
                },
                Case {
                    scenario: "negative below lower bound",
                    input: -1,
                    expect: Fails,
                },
                Case {
                    scenario: "large",
                    input: 1000,
                    expect: Fails,
                },
            ],
            |level| IBServiceLevel::try_from(level).map_err(drop),
        );
    }

    #[test]
    fn service_level_into_i32() {
        check_values(
            [
                Check {
                    scenario: "0",
                    input: IBServiceLevel(0),
                    expect: 0,
                },
                Check {
                    scenario: "15",
                    input: IBServiceLevel(15),
                    expect: 15,
                },
            ],
            i32::from,
        );
    }
}
