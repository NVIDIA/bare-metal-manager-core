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
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
#[cfg(feature = "ipnetwork")]
use ipnetwork::IpNetwork;

/// DEFAULT_NETWORK_VIRTUALIZATION_TYPE is what to default to if the Cloud API
/// doesn't send it to Carbide (which it never does), or if the Carbide API
/// doesn't send it to the DPU agent.
pub const DEFAULT_NETWORK_VIRTUALIZATION_TYPE: VpcVirtualizationType =
    VpcVirtualizationType::EthernetVirtualizer;

/// VpcVirtualizationType is the type of network virtualization
/// being used for the environment. This is currently stored in the
/// database at the VPC level, but not actually plumbed down to the
/// DPU agent. Instead, the DPU agent just gets fed a
/// NetworkVirtualizationType based on the value of `nvue_enabled`.
///
/// The idea is with FNN, we'll actually mark a VPC as ETV or FNN,
/// and plumb the value down to the DPU agent, which gets piped into
/// the `update_nvue` function, which is then used to drive
/// population of the appropriate template.
///
// TODO(chet): Rename
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "network_virtualization_type_t"))]
pub enum VpcVirtualizationType {
    #[cfg_attr(feature = "sqlx", sqlx(rename = "etv"))]
    EthernetVirtualizer,
    #[cfg_attr(feature = "sqlx", sqlx(rename = "etv_nvue"))]
    EthernetVirtualizerWithNvue,
    #[cfg_attr(feature = "sqlx", sqlx(rename = "fnn"))]
    Fnn,
}

impl VpcVirtualizationType {
    pub fn supports_nvue(&self) -> bool {
        match self {
            Self::EthernetVirtualizer => false,
            Self::EthernetVirtualizerWithNvue => true,
            Self::Fnn => true,
        }
    }
}

impl Default for VpcVirtualizationType {
    fn default() -> Self {
        Self::EthernetVirtualizer
    }
}

impl fmt::Display for VpcVirtualizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EthernetVirtualizer => write!(f, "etv"),
            Self::EthernetVirtualizerWithNvue => write!(f, "etv_nvue"),
            Self::Fnn => write!(f, "fnn"),
        }
    }
}

impl TryFrom<i32> for VpcVirtualizationType {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::VpcVirtualizationType::EthernetVirtualizer as i32 => {
                Self::EthernetVirtualizer
            }
            x if x == rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32 => {
                Self::EthernetVirtualizerWithNvue
            }
            x if x == rpc::VpcVirtualizationType::Fnn as i32 => Self::Fnn,
            _ => {
                return Err(RpcDataConversionError::InvalidVpcVirtualizationType(value));
            }
        })
    }
}

impl From<rpc::VpcVirtualizationType> for VpcVirtualizationType {
    fn from(v: rpc::VpcVirtualizationType) -> Self {
        match v {
            rpc::VpcVirtualizationType::EthernetVirtualizer => Self::EthernetVirtualizer,
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                Self::EthernetVirtualizerWithNvue
            }
            rpc::VpcVirtualizationType::Fnn => Self::Fnn,
            // Following are deprecated.
            rpc::VpcVirtualizationType::FnnClassic => Self::Fnn,
            rpc::VpcVirtualizationType::FnnL3 => Self::Fnn,
        }
    }
}

impl From<VpcVirtualizationType> for rpc::VpcVirtualizationType {
    fn from(nvt: VpcVirtualizationType) -> Self {
        match nvt {
            VpcVirtualizationType::EthernetVirtualizer => {
                rpc::VpcVirtualizationType::EthernetVirtualizer
            }
            VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue
            }
            VpcVirtualizationType::Fnn => rpc::VpcVirtualizationType::Fnn,
        }
    }
}

impl FromStr for VpcVirtualizationType {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "etv" => Ok(Self::EthernetVirtualizer),
            "etv_nvue" => Ok(Self::EthernetVirtualizerWithNvue),
            "fnn" => Ok(Self::Fnn),
            x => Err(eyre::eyre!(format!("Unknown virt type {}", x))),
        }
    }
}

#[cfg(feature = "ipnetwork")]
/// get_host_ip returns the host IP for a tenant instance
/// for a given IpNetwork. This is being initially introduced
/// for the purpose of FNN /30 allocations (where the host IP
/// ends up being the 4th IP -- aka the second IP of the second
/// /31 allocation in the /30), and will probably change with
/// a wider refactor + intro of Carbide IP Prefix Management.
pub fn get_host_ip(network: &IpNetwork) -> eyre::Result<std::net::IpAddr> {
    match network.prefix() {
        32 => Ok(network.ip()),
        30 => match network.iter().nth(3) {
            Some(ip_addr) => Ok(ip_addr),
            None => Err(eyre::eyre!(format!(
                "no viable host IP found in network: {}",
                network
            ))),
        },
        _ => Err(eyre::eyre!(format!(
            "tenant instance network size unsupported: {}",
            network.prefix()
        ))),
    }
}

#[cfg(feature = "ipnetwork")]
/// get_svi_ip returns the SVI IP (also known as the gateway IP)
/// for a tenant instance for a given IpNetwork. This is valid only for l2 segments under FNN.
pub fn get_svi_ip(
    svi_ip: &Option<std::net::IpAddr>,
    virtualization_type: VpcVirtualizationType,
    is_l2_segment: bool,
    prefix: u8,
) -> eyre::Result<Option<IpNetwork>> {
    if virtualization_type == VpcVirtualizationType::Fnn && is_l2_segment {
        let Some(svi_ip) = svi_ip else {
            return Err(eyre::eyre!(format!("SVI IP is not allocated.",)));
        };

        return Ok(Some(IpNetwork::new(*svi_ip, prefix)?));
    }
    Ok(None)
}
