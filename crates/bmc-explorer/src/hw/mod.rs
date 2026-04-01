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

use std::fmt;

use itertools::Itertools;

pub mod bluefield;
pub mod dell;
pub mod gb200;
pub mod hpe;
pub mod lenovo;
pub mod lenovo_ami;
pub mod lenovo_gb300;
pub mod supermicro;
pub mod viking;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwType {
    Ami,
    Bluefield,
    Dell,
    Gb200,
    Hpe,
    Lenovo,
    LenovoAmi,
    LenovoGb300,
    Supermicro,
    Viking,
    LiteonPowerShelf,
    NvSwitch,
}

impl HwType {
    pub const fn bmc_vendor(&self) -> Option<bmc_vendor::BMCVendor> {
        match self {
            Self::Ami => None,
            Self::Bluefield => Some(bmc_vendor::BMCVendor::Nvidia),
            Self::Dell => Some(bmc_vendor::BMCVendor::Dell),
            Self::Gb200 => Some(bmc_vendor::BMCVendor::Nvidia),
            Self::Hpe => Some(bmc_vendor::BMCVendor::Hpe),
            Self::Lenovo => Some(bmc_vendor::BMCVendor::Lenovo),
            Self::LenovoAmi => Some(bmc_vendor::BMCVendor::LenovoAMI),
            Self::LenovoGb300 => Some(bmc_vendor::BMCVendor::LenovoAMI),
            Self::LiteonPowerShelf => Some(bmc_vendor::BMCVendor::Liteon),
            Self::NvSwitch => Some(bmc_vendor::BMCVendor::Nvidia),
            Self::Supermicro => Some(bmc_vendor::BMCVendor::Supermicro),
            Self::Viking => Some(bmc_vendor::BMCVendor::Nvidia),
        }
    }

    pub const fn infinite_boot_enabled_attr(&self) -> Option<BiosAttr<'static>> {
        match self {
            Self::Ami => Some(BiosAttr::new_str("EndlessBoot", "Enabled")),
            Self::Bluefield => None,
            Self::Dell => Some(BiosAttr::new_str("BootSeqRetry", "Enabled")),
            Self::Gb200 => Some(BiosAttr::new_str("EmbeddedUefiShell", "Disabled")),
            Self::Hpe => None,
            Self::Lenovo => Some(BiosAttr::new_str("BootModes_InfiniteBootRetry", "Enabled")),
            Self::LenovoAmi => Some(BiosAttr::new_str("EndlessBoot", "Enabled")),
            Self::LenovoGb300 => Some(BiosAttr::new_int("LEM0003", 50)),
            Self::LiteonPowerShelf => None,
            Self::NvSwitch => None,
            Self::Supermicro => None,
            Self::Viking => Some(BiosAttr::new_str("NvidiaInfiniteboot", "Enable")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct BiosAttr<'a> {
    pub key: &'a str,
    pub value: BiosAttrValue<'a>,
}

impl BiosAttr<'_> {
    pub const fn new_bool(key: &'static str, value: bool) -> BiosAttr<'static> {
        BiosAttr {
            key,
            value: BiosAttrValue::Bool(value),
        }
    }
    pub const fn new_str(key: &'static str, value: &'static str) -> BiosAttr<'static> {
        BiosAttr {
            key,
            value: BiosAttrValue::Str(value),
        }
    }
    pub const fn new_any_str(
        key: &'static str,
        value: &'static [&'static str],
    ) -> BiosAttr<'static> {
        BiosAttr {
            key,
            value: BiosAttrValue::AnyStr(value),
        }
    }
    pub const fn new_int(key: &'static str, value: i64) -> BiosAttr<'static> {
        BiosAttr {
            key,
            value: BiosAttrValue::Int(value),
        }
    }
}

#[derive(Clone, Copy)]
pub enum BiosAttrValue<'a> {
    Str(&'a str),
    AnyStr(&'a [&'a str]),
    Bool(bool),
    Int(i64),
}

impl fmt::Display for BiosAttrValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiosAttrValue::Str(v) => v.fmt(f),
            BiosAttrValue::Bool(v) => v.fmt(f),
            BiosAttrValue::Int(v) => v.fmt(f),
            BiosAttrValue::AnyStr(v) => write!(f, "any({})", v.iter().join(",")),
        }
    }
}
