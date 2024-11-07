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

use serde::{Deserialize, Serialize};

use crate::CarbideError;

pub const IBNETWORK_DEFAULT_MEMBERSHIP: IBPortMembership = IBPortMembership::Full;
pub const IBNETWORK_DEFAULT_INDEX0: bool = true;

#[derive(Clone, Debug)]
pub struct IBNetwork {
    /// The name of IB network.
    pub name: String,
    /// The pkey of IB network.
    pub pkey: u16,
    /// Default false; create sharp allocation accordingly.
    pub enable_sharp: bool,
    /// Default 2k; one of 2k or 4k; the MTU of the services.
    pub mtu: IBMtu,
    /// Default false
    pub ipoib: bool,
    /// Default is None, value can be range from 0-15.
    pub service_level: IBServiceLevel,
    /// The default membership of IB network.
    pub membership: IBPortMembership,
    /// The default index0 of IB network.
    pub index0: bool,
    /// Default is None, can be one of the following: 10, 30, 5, 20, 40, 60, 80, 120, 14, 56, 112, 168, 25, 100, 200, or 300.
    /// NOTE: 2.5 is also a valid value in UFM for lagecy hardware which is not the case of Carbide.
    pub rate_limit: IBRateLimit,
}

#[derive(Clone, PartialEq, Debug)]
pub enum IBPortState {
    Active,
    Down,
}

#[derive(Clone, Debug)]
pub enum IBPortMembership {
    Full,
    Limited,
}

#[derive(Clone, Debug)]
pub struct IBPort {
    pub name: String,
    pub guid: String,
    pub lid: i32,
    pub state: Option<IBPortState>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBMtu(pub i32);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBRateLimit(pub i32);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IBServiceLevel(pub i32);

impl Default for IBMtu {
    fn default() -> IBMtu {
        IBMtu(4)
    }
}

impl TryFrom<i32> for IBMtu {
    type Error = CarbideError;

    fn try_from(mtu: i32) -> Result<Self, Self::Error> {
        match mtu {
            2 | 4 => Ok(Self(mtu)),
            _ => Err(CarbideError::InvalidArgument(format!(
                "{0} is an invalid MTU",
                mtu
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
    type Error = CarbideError;

    fn try_from(rate_limit: i32) -> Result<Self, Self::Error> {
        match rate_limit {
            10 | 30 | 5 | 20 | 40 | 60 | 80 | 120 | 14 | 56 | 112 | 168 | 25 | 100 | 200 | 300 => {
                Ok(Self(rate_limit))
            }
            _ => Err(CarbideError::InvalidArgument(format!(
                "{0} is an invalid rate limit",
                rate_limit
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
    // NOTES: Highlight the default value of service_level which is
    // the same value of i32.
    #[allow(clippy::derivable_impls)]
    fn default() -> IBServiceLevel {
        IBServiceLevel(0)
    }
}

impl TryFrom<i32> for IBServiceLevel {
    type Error = CarbideError;

    fn try_from(service_level: i32) -> Result<Self, Self::Error> {
        match service_level {
            0..=15 => Ok(Self(service_level)),

            _ => Err(CarbideError::InvalidArgument(format!(
                "{0} is an invalid service level",
                service_level
            ))),
        }
    }
}

impl From<IBServiceLevel> for i32 {
    fn from(service_level: IBServiceLevel) -> i32 {
        service_level.0
    }
}
