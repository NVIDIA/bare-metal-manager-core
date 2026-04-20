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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpcVirtualizationType {
    EthernetVirtualizer,
    EthernetVirtualizerWithNvue,
    Fnn,
}

// Manual sqlx impls so that legacy DB value 'etv' decodes as EthernetVirtualizerWithNvue.
#[cfg(feature = "sqlx")]
const PG_TYPE_NAME: &str = "network_virtualization_type_t";

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Postgres> for VpcVirtualizationType {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name(PG_TYPE_NAME)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Encode<'_, sqlx::Postgres> for VpcVirtualizationType {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let s = match self {
            Self::EthernetVirtualizer | Self::EthernetVirtualizerWithNvue => "etv",
            Self::Fnn => "fnn",
        };
        <&str as sqlx::Encode<sqlx::Postgres>>::encode(s, buf)
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::postgres::PgHasArrayType for VpcVirtualizationType {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("_network_virtualization_type_t")
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Decode<'_, sqlx::Postgres> for VpcVirtualizationType {
    fn decode(value: sqlx::postgres::PgValueRef<'_>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        match s {
            "etv" | "etv_nvue" => Ok(Self::EthernetVirtualizer),
            "fnn" => Ok(Self::Fnn),
            other => {
                Err(format!("invalid value {:?} for enum VpcVirtualizationType", other).into())
            }
        }
    }
}

#[cfg(all(test, feature = "sqlx"))]
mod sqlx_tests {
    use sqlx::Encode;
    use sqlx::postgres::PgArgumentBuffer;

    use super::VpcVirtualizationType;

    fn encode_to_string(v: VpcVirtualizationType) -> String {
        let mut buf = PgArgumentBuffer::default();
        let _ = v.encode_by_ref(&mut buf).unwrap();
        String::from_utf8(buf.to_vec()).unwrap()
    }

    #[test]
    fn encode_etv_writes_etv() {
        assert_eq!(
            encode_to_string(VpcVirtualizationType::EthernetVirtualizer),
            "etv"
        );
    }

    #[test]
    fn encode_etv_nvue_writes_etv() {
        assert_eq!(
            encode_to_string(VpcVirtualizationType::EthernetVirtualizerWithNvue),
            "etv"
        );
    }

    #[test]
    fn encode_fnn_writes_fnn() {
        assert_eq!(encode_to_string(VpcVirtualizationType::Fnn), "fnn");
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
            Self::EthernetVirtualizer | Self::EthernetVirtualizerWithNvue => write!(f, "etv"),
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
            // If we get proto enum field 2, which is ETHERNET_VIRTUALIZER_WITH_NVUE,
            // just map it to EthernetVirtualizer.
            x if x == rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32 => {
                Self::EthernetVirtualizer
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
            // ETHERNET_VIRTUALIZER_WITH_NVUE is equivalent to EthernetVirtualizer
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue => Self::EthernetVirtualizer,
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
            VpcVirtualizationType::EthernetVirtualizer
            | VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                rpc::VpcVirtualizationType::EthernetVirtualizer
            }
            VpcVirtualizationType::Fnn => rpc::VpcVirtualizationType::Fnn,
        }
    }
}

/// Concatenate a required IPv4 value with an optional IPv6 value into a vector.
/// Empty IPv6 strings are filtered out.
pub fn build_dual_stack_list(v4: String, v6: Option<String>) -> Vec<String> {
    std::iter::once(v4)
        .chain(v6.filter(|s| !s.is_empty()))
        .collect()
}

impl FromStr for VpcVirtualizationType {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "etv" | "etv_nvue" => Ok(Self::EthernetVirtualizer),
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
        // Single-host allocation: IPv4 /32 or IPv6 /128
        32 | 128 => Ok(network.ip()),
        // Point-to-point linknet: IPv4 /31 (RFC 3021) or IPv6 /127 (RFC 6164)
        // The second address is the host IP.
        31 | 127 => match network.iter().nth(1) {
            Some(ip_addr) => Ok(ip_addr),
            None => Err(eyre::eyre!(
                "no viable host IP found in point-to-point network: {}",
                network
            )),
        },
        // Legacy /30 allocation: host IP is the 4th address
        30 => match network.iter().nth(3) {
            Some(ip_addr) => Ok(ip_addr),
            None => Err(eyre::eyre!(
                "no viable host IP found in network: {}",
                network
            )),
        },
        _ => Err(eyre::eyre!(
            "tenant instance network size unsupported: {}",
            network.prefix()
        )),
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn from_str_etv_nvue_maps_to_etv() {
        assert_eq!(
            "etv_nvue".parse::<VpcVirtualizationType>().unwrap(),
            VpcVirtualizationType::EthernetVirtualizer
        );
    }

    #[test]
    fn from_str_etv_maps_to_etv() {
        assert_eq!(
            "etv".parse::<VpcVirtualizationType>().unwrap(),
            VpcVirtualizationType::EthernetVirtualizer
        );
    }

    #[test]
    fn proto_value_2_maps_to_etv() {
        // Make sure our proto From implementation turns
        // ETHERNET_VIRTUALIZER_WITH_NVUE into EthernetVirtualizer.
        let vtype = VpcVirtualizationType::try_from(2).unwrap();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn proto_value_0_maps_to_etv() {
        let vtype = VpcVirtualizationType::try_from(0).unwrap();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn from_rpc_etv_with_nvue_maps_to_etv() {
        let vtype: VpcVirtualizationType =
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue.into();
        assert_eq!(vtype, VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn to_rpc_etv_maps_to_proto_etv() {
        let rpc_vtype: rpc::VpcVirtualizationType =
            VpcVirtualizationType::EthernetVirtualizer.into();
        assert_eq!(rpc_vtype, rpc::VpcVirtualizationType::EthernetVirtualizer);
    }

    #[test]
    fn display_etv_with_nvue_shows_etv() {
        assert_eq!(
            VpcVirtualizationType::EthernetVirtualizerWithNvue.to_string(),
            "etv"
        );
    }

    #[test]
    fn test_get_host_ip_ipv4_slash32() {
        let network = IpNetwork::new("10.0.0.5".parse().unwrap(), 32).unwrap();
        let result = get_host_ip(&network).unwrap();
        assert_eq!(result, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_host_ip_ipv6_slash128() {
        let network = IpNetwork::new("2001:db8::1".parse().unwrap(), 128).unwrap();
        let result = get_host_ip(&network).unwrap();
        assert_eq!(result, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_host_ip_ipv4_slash31_point_to_point() {
        let network = IpNetwork::new("10.0.0.0".parse().unwrap(), 31).unwrap();
        let result = get_host_ip(&network).unwrap();
        assert_eq!(result, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_host_ip_ipv6_slash127_point_to_point() {
        let network = IpNetwork::new("2001:db8::0".parse().unwrap(), 127).unwrap();
        let result = get_host_ip(&network).unwrap();
        assert_eq!(result, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_host_ip_ipv4_slash30_legacy() {
        let network = IpNetwork::new("10.0.0.0".parse().unwrap(), 30).unwrap();
        let result = get_host_ip(&network).unwrap();
        assert_eq!(result, "10.0.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_host_ip_unsupported_prefix() {
        let network = IpNetwork::new("10.0.0.0".parse().unwrap(), 29).unwrap();
        let result = get_host_ip(&network);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }
}
