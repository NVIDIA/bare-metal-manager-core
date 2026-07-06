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

use std::net::IpAddr;

use carbide_uuid::domain::DomainId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use clap::Parser;
use ipnet::IpNet;
use rpc::forge;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Create a tenant network segment with an IPv4 prefix:
    $ nico-admin-cli --cloud-unsafe-op=my_username network-segment create --name tenant-segment-1 --vpc-id 12345678-1234-5678-90ab-cdef01234567 --prefix 10.0.0.0/24 --gateway 10.0.0.1

Create a dual-stack host in-band segment with a chosen ID:
    $ nico-admin-cli --cloud-unsafe-op=my_username network-segment create --name host-inband-a --segment-type host-inband --id 12345678-1234-5678-90ab-cdef01234567 --prefix 192.0.2.0/24 --gateway 192.0.2.1 --prefix 2001:db8::/64 --dhcpv6-link-address fe80::1 --subdomain-id 3ea8d9a2-4fe3-4189-97fc-cf9134e31f8f

")]
pub struct Args {
    #[clap(long, help = "Network segment name")]
    pub name: String,

    #[clap(
        long,
        value_name = "NetworkSegmentId",
        help = "Optional network segment ID to use instead of allowing the API server to generate one"
    )]
    pub id: Option<NetworkSegmentId>,

    #[clap(
        long,
        value_name = "VpcId",
        help = "Optional VPC ID to attach the new segment to"
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(
        long,
        value_name = "DomainId",
        help = "DNS subdomain ID used for DHCP and DNS records on the segment. Required for segments of type host-inband"
    )]
    pub subdomain_id: Option<DomainId>,

    #[clap(
        long,
        value_name = "MTU",
        help = "Optional MTU for the segment. Defaults to 9000 for tenant segments and 1500 for other segment types"
    )]
    pub mtu: Option<i32>,

    #[clap(
        long,
        name = "prefix",
        value_name = "CIDR-prefix",
        help = "Network prefix in CIDR notation. Repeat once per address family",
        action = clap::ArgAction::Append,
        required = true
    )]
    pub prefix: Vec<IpNet>,

    #[clap(
        long,
        value_name = "IP-address",
        help = "IPv4 gateway for the IPv4 prefix"
    )]
    pub gateway: Option<IpAddr>,

    #[clap(
        long,
        name = "dhcpv6-link-address",
        value_name = "IPv6-address",
        help = "DHCPv6 relay link-address for the IPv6 prefix"
    )]
    pub dhcpv6_link_address: Option<IpAddr>,

    #[clap(
        long,
        default_value_t = 0,
        value_name = "COUNT",
        help = "Number of addresses to reserve before dynamic allocation starts"
    )]
    pub reserve_first: i32,

    #[clap(
        long,
        value_enum,
        default_value = "tenant",
        help = "Network segment type"
    )]
    pub segment_type: forge::NetworkSegmentType,
}

impl From<Args> for forge::NetworkSegmentCreationRequest {
    fn from(args: Args) -> Self {
        let prefixes = args
            .prefix
            .into_iter()
            .map(|prefix| forge::NetworkPrefix {
                id: None,
                prefix: prefix.to_string(),
                gateway: args.gateway.map(|gw| gw.to_string()),
                reserve_first: args.reserve_first,
                free_ip_count: 0,
                svi_ip: None,
            })
            .collect();

        Self {
            vpc_id: args.vpc_id,
            name: args.name,
            subdomain_id: args.subdomain_id,
            mtu: args.mtu,
            prefixes,
            segment_type: args.segment_type as i32,
            id: args.id,
        }
    }
}
