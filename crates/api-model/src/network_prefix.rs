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

use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPrefix {
    pub id: NetworkPrefixId,
    pub segment_id: NetworkSegmentId,
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub num_reserved: i32,
    pub vpc_prefix_id: Option<VpcPrefixId>,
    pub vpc_prefix: Option<IpNetwork>,
    pub svi_ip: Option<IpAddr>,
    #[serde(default)]
    pub num_free_ips: u32,
}

#[derive(Debug)]
pub struct NewNetworkPrefix {
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub num_reserved: i32,
}

impl<'r> FromRow<'r, PgRow> for NetworkPrefix {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(NetworkPrefix {
            id: row.try_get("id")?,
            segment_id: row.try_get("segment_id")?,
            vpc_prefix_id: row.try_get("vpc_prefix_id")?,
            vpc_prefix: row.try_get("vpc_prefix")?,
            prefix: row.try_get("prefix")?,
            gateway: row.try_get("gateway")?,
            num_reserved: row.try_get("num_reserved")?,
            svi_ip: row.try_get("svi_ip")?,
            num_free_ips: 0,
        })
    }
}

impl TryFrom<rpc::forge::NetworkPrefix> for NewNetworkPrefix {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::NetworkPrefix) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
            return Err(RpcDataConversionError::IdentifierSpecifiedForNewObject(
                String::from("Network Prefix"),
            ));
        }

        Ok(NewNetworkPrefix {
            prefix: value.prefix.parse()?,
            gateway: match value.gateway {
                Some(g) => Some(
                    g.parse()
                        .map_err(|_| RpcDataConversionError::InvalidIpAddress(g))?,
                ),
                None => None,
            },
            num_reserved: value.reserve_first,
        })
    }
}

impl From<NetworkPrefix> for rpc::forge::NetworkPrefix {
    fn from(src: NetworkPrefix) -> Self {
        rpc::forge::NetworkPrefix {
            id: Some(src.id),
            prefix: src.prefix.to_string(),
            gateway: src.gateway.map(|v| v.to_string()),
            reserve_first: src.num_reserved,
            free_ip_count: src.num_free_ips,
            svi_ip: src.svi_ip.map(|x| x.to_string()),
        }
    }
}

impl NetworkPrefix {
    pub fn gateway_cidr(&self) -> Option<String> {
        // TODO: This was here before, but seems broken
        // The gateway address should always be a /32
        // Should we directly return the prefix?
        self.gateway
            .map(|g| format!("{}/{}", g, self.prefix.prefix()))
    }

    // We use this to try to guess whether an associated segment is stretchable
    // in cases where the database doesn't contain that information.
    pub fn smells_like_fnn(&self) -> bool {
        self.vpc_prefix_id.is_some()
            && match self.prefix {
                // A 31 network prefix is used for FNN.
                IpNetwork::V4(v4) => v4.prefix() >= 30,
                IpNetwork::V6(_) => {
                    // We don't have any IPv6 segment prefixes at the time of
                    // writing so we don't really expect this arm to match, but
                    // let's provide a safe value just in case.
                    false
                }
            }
    }
}
