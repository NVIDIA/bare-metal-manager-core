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

use std::str::FromStr;

use ::rpc::admin_cli::CarbideCliError;
use ::rpc::admin_cli::CarbideCliError::GenericError;
use carbide_uuid::vpc::VpcPrefixId;
use ipnet::IpNet;
use rpc::forge::{PrefixMatchType, VpcPrefix, VpcPrefixSearchQuery};

use crate::rpc::ApiClient;

#[derive(Clone, Debug)]
pub enum VpcPrefixSelector {
    Id(VpcPrefixId),
    Prefix(ipnet::IpNet),
}

impl VpcPrefixSelector {
    pub async fn fetch(self, api_client: &ApiClient) -> Result<VpcPrefix, CarbideCliError> {
        match self {
            VpcPrefixSelector::Id(id) => get_one_by_id(api_client, id).await,
            VpcPrefixSelector::Prefix(prefix) => {
                let id = {
                    let uuids = search(api_client, prefix_match_exact(&prefix)).await?;
                    let uuid = match Quantity::from(uuids) {
                        Quantity::One(uuid) => Ok(uuid),
                        Quantity::Zero => Err(GenericError(format!(
                            "No VPC prefix matched IP prefix {prefix} (either \
                            such a prefix does not exist, or it's a different size)"
                        ))),
                        Quantity::Many(uuids) => Err(GenericError(format!(
                            "Multiple VPC prefixes matched IP prefix {prefix}: {uuids:?}"
                        ))),
                    };
                    uuid.and_then(|uuid| {
                        VpcPrefixId::try_from(uuid).map_err(|e| {
                            GenericError(format!("Cannot parse VpcPrefixId from API: {e}"))
                        })
                    })
                }?;
                get_one_by_id(api_client, id).await
            }
        }
    }
}

impl FromStr for VpcPrefixSelector {
    type Err = CarbideCliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed_vpc_prefix_id = VpcPrefixId::from_str(s);
        let parsed_ip_prefix = ipnet::IpNet::from_str(s);
        match (parsed_ip_prefix, parsed_vpc_prefix_id) {
            (Ok(ip_prefix), _) => Ok(Self::Prefix(ip_prefix)),
            (Err(_), Ok(vpc_prefix_id)) => Ok(Self::Id(vpc_prefix_id)),
            (Err(prefix_parse_error), Err(id_parse_error)) => Err(GenericError(format!(
                "Couldn't parse VPC prefix selector as VpcPrefixId ({id_parse_error}) or as IP prefix ({prefix_parse_error})"
            ))),
        }
    }
}

pub fn prefix_match_exact(prefix: &IpNet) -> VpcPrefixSearchQuery {
    VpcPrefixSearchQuery {
        prefix_match: Some(prefix.to_string()),
        prefix_match_type: Some(PrefixMatchType::PrefixExact as i32),
        ..Default::default()
    }
}

pub fn match_all() -> VpcPrefixSearchQuery {
    VpcPrefixSearchQuery {
        ..Default::default()
    }
}

pub async fn search(
    api_client: &ApiClient,
    query: VpcPrefixSearchQuery,
) -> Result<Vec<VpcPrefixId>, CarbideCliError> {
    Ok(api_client
        .0
        .search_vpc_prefixes(query)
        .await
        .map(|response| response.vpc_prefix_ids)?)
}

pub async fn get_by_ids(
    api_client: &ApiClient,
    batch_size: usize,
    ids: &[VpcPrefixId],
) -> Result<Vec<VpcPrefix>, CarbideCliError> {
    let mut vpc_prefixes = Vec::with_capacity(ids.len());
    for ids in ids.chunks(batch_size) {
        let vpc_id_list = rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: ids.to_owned(),
        };
        let prefixes_batch = api_client
            .0
            .get_vpc_prefixes(vpc_id_list)
            .await
            .map(|response| response.vpc_prefixes)?;
        vpc_prefixes.extend(prefixes_batch);
    }
    Ok(vpc_prefixes)
}

pub async fn get_one_by_id(
    api_client: &ApiClient,
    id: VpcPrefixId,
) -> Result<VpcPrefix, CarbideCliError> {
    let mut prefixes = get_by_ids(api_client, 1, &[id]).await?;
    match (prefixes.len(), prefixes.pop()) {
        (1, Some(prefix)) => Ok(prefix),
        (0, None) => Err(CarbideCliError::GenericError(format!(
            "VPC prefix not found: {id}"
        ))),
        (n, _) => {
            panic!(
                "Requested a single VPC prefix ID ({id}) from the API but \
                {n} were returned (this shouldn't happen, please file a bug)"
            )
        }
    }
}

pub enum Quantity<T> {
    Zero,
    One(T),
    Many(Vec<T>),
}

impl<T> From<Vec<T>> for Quantity<T> {
    fn from(value: Vec<T>) -> Self {
        let mut items = value;
        match items.len() {
            0 => Quantity::Zero,
            1 => Quantity::One(items.pop().unwrap()),
            _ => Quantity::Many(items),
        }
    }
}
