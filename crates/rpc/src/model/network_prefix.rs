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

use model::network_prefix::{NetworkPrefix, NewNetworkPrefix};

use crate as rpc;
use crate::errors::RpcDataConversionError;

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
