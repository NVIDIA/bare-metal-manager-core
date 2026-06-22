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

use ::rpc::admin_cli::OutputFormat;
use ipnet::IpNet;

use super::args::Args;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

pub async fn handle_create_reverse(
    args: &Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let zone = cidr_to_reverse_zone(args.cidr)?;
    let domain = api_client.create_domain(&zone).await?;
    if output_format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&domain)?);
    } else {
        println!(
            "Created reverse zone '{}' for {} ({})",
            domain.name,
            args.cidr,
            domain.id.unwrap_or_default()
        );
    }
    Ok(())
}

/// Derive the reverse-DNS zone name for a CIDR: the network octets (IPv4) or
/// nibbles (IPv6) in reverse order, under `in-addr.arpa` / `ip6.arpa`. The prefix
/// must be octet-aligned for IPv4 (/8, /16, /24, /32) or nibble-aligned for IPv6
/// (a multiple of 4); RFC 2317 classless delegation is out of scope.
pub(crate) fn cidr_to_reverse_zone(cidr: IpNet) -> CarbideCliResult<String> {
    match cidr {
        IpNet::V4(net) => {
            let prefix = net.prefix_len();
            if prefix == 0 || prefix % 8 != 0 {
                return Err(CarbideCliError::InvalidReverseZoneCidr(format!(
                    "IPv4 reverse zones need an octet-aligned prefix (/8, /16, /24, /32), got /{prefix}"
                )));
            }
            let labels = (prefix / 8) as usize;
            let mut parts: Vec<String> = net.network().octets()[..labels]
                .iter()
                .rev()
                .map(u8::to_string)
                .collect();
            parts.push("in-addr.arpa".to_string());
            Ok(parts.join("."))
        }
        IpNet::V6(net) => {
            let prefix = net.prefix_len();
            if prefix == 0 || prefix % 4 != 0 {
                return Err(CarbideCliError::InvalidReverseZoneCidr(format!(
                    "IPv6 reverse zones need a nibble-aligned prefix (a multiple of 4), got /{prefix}"
                )));
            }
            let octets = net.network().octets();
            let nibbles = (prefix / 4) as usize;
            let mut parts: Vec<String> = (0..nibbles)
                .map(|i| {
                    let byte = octets[i / 2];
                    let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
                    format!("{nibble:x}")
                })
                .collect();
            parts.reverse();
            parts.push("ip6.arpa".to_string());
            Ok(parts.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::cidr_to_reverse_zone;

    #[test]
    fn derives_reverse_zone_from_cidr() {
        scenarios!(
            run = |cidr: &str| cidr_to_reverse_zone(cidr.parse().unwrap()).map_err(drop);
            "ipv4 octet-aligned prefixes" {
                "10.0.0.0/8" => Yields("10.in-addr.arpa".to_string()),
                "192.168.0.0/16" => Yields("168.192.in-addr.arpa".to_string()),
                "192.0.2.0/24" => Yields("2.0.192.in-addr.arpa".to_string()),
                "192.0.2.1/32" => Yields("1.2.0.192.in-addr.arpa".to_string()),
            }
            "ipv6 nibble-aligned prefixes" {
                "fd00::/16" => Yields("0.0.d.f.ip6.arpa".to_string()),
                "2001:db8::/32" => Yields("8.b.d.0.1.0.0.2.ip6.arpa".to_string()),
            }
            "host bits below the prefix are ignored" {
                "192.168.5.7/16" => Yields("168.192.in-addr.arpa".to_string()),
            }
            "rejects prefixes that are not octet- or nibble-aligned" {
                "192.168.0.0/25" => Fails,
                "fd00::/17" => Fails,
                "0.0.0.0/0" => Fails,
            }
        );
    }
}
