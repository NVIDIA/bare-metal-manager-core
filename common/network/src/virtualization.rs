/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use ipnetwork::IpNetwork;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "network_virtualization_type_t")]
#[allow(clippy::enum_variant_names)]
pub enum VpcVirtualizationType {
    #[sqlx(rename = "etv")]
    EthernetVirtualizer = 0,
    #[sqlx(rename = "etv_nvue")]
    EthernetVirtualizerWithNvue = 2,
    #[sqlx(rename = "fnn_classic")]
    FnnClassic = 3,
    #[sqlx(rename = "fnn_l3")]
    FnnL3 = 4,
}

impl VpcVirtualizationType {
    pub fn prefix_length(&self) -> u8 {
        match self {
            Self::EthernetVirtualizer => 32,
            Self::EthernetVirtualizerWithNvue => 32,
            Self::FnnClassic => 32,
            Self::FnnL3 => 30,
        }
    }
}

impl fmt::Display for VpcVirtualizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EthernetVirtualizer => write!(f, "etv"),
            Self::EthernetVirtualizerWithNvue => write!(f, "etv_nvue"),
            Self::FnnClassic => write!(f, "fnn_classic"),
            Self::FnnL3 => write!(f, "fnn_l3"),
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
            x if x == rpc::VpcVirtualizationType::FnnClassic as i32 => Self::FnnClassic,
            x if x == rpc::VpcVirtualizationType::FnnL3 as i32 => Self::FnnL3,
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
            rpc::VpcVirtualizationType::FnnClassic => Self::FnnClassic,
            rpc::VpcVirtualizationType::FnnL3 => Self::FnnL3,
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
            VpcVirtualizationType::FnnClassic => rpc::VpcVirtualizationType::FnnClassic,
            VpcVirtualizationType::FnnL3 => rpc::VpcVirtualizationType::FnnL3,
        }
    }
}

impl FromStr for VpcVirtualizationType {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "etv" => Ok(Self::EthernetVirtualizer),
            "etv_nvue" => Ok(Self::EthernetVirtualizerWithNvue),
            "fnn_classic" => Ok(Self::FnnClassic),
            "fnn_l3" => Ok(Self::FnnL3),
            x => Err(eyre::eyre!(format!("Unknown virt type {}", x))),
        }
    }
}

/// get_host_ip returns the host IP for a tenant instance
/// for a given IpNetwork. This is being initially introduced
/// for the purpose of FNN /30 allocations (where the host IP
/// ends up being the 4th IP -- aka the second IP of the second
/// /31 allocation in the /30), and will probably change with
/// a wider refactor + intro of Carbide IP Prefix Management.
pub fn get_host_ip(network: &IpNetwork) -> eyre::Result<IpAddr> {
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

/// get_svi_ip returns the SVI IP (also known as the gateway IP)
/// for a tenant instance for a given IpNetwork. This is being
/// initially introduced for the purpose of FNN /30 allocations
/// (where the SVI IP ends up being the 3rd IP -- aka the first
/// IP of the second /31 allocation in the /30), and will probably
/// change with a wider refactor + intro of Carbide IP Prefix Management.
pub fn get_svi_ip(network: &IpNetwork) -> eyre::Result<Option<IpAddr>> {
    match network.prefix() {
        32 => Ok(None),
        30 => match network.iter().nth(2) {
            Some(ip_addr) => Ok(Some(ip_addr)),
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
