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

use std::borrow::Cow;
use std::str::FromStr;

use ::rpc::admin_cli::CarbideCliError::GenericError;
use ::rpc::admin_cli::output::{FormattedOutput, IntoTable, OutputFormat};
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use carbide_uuid::vpc::VpcPrefixId;
use ipnet::IpNet;
use rpc::forge::{
    PrefixMatchType, VpcPrefix, VpcPrefixCreationRequest, VpcPrefixDeletionRequest,
    VpcPrefixSearchQuery,
};
use serde::Serialize;

use super::args::{VpcPrefixCreate, VpcPrefixDelete, VpcPrefixShow};
use crate::rpc::ApiClient;

pub async fn show(
    args: VpcPrefixShow,
    output_format: OutputFormat,
    api_client: &ApiClient,
    batch_size: usize,
) -> CarbideCliResult<()> {
    let show_method = ShowMethod::from(args);
    let output = fetch(api_client, batch_size, show_method).await?;

    output
        .write_output(output_format, ::rpc::admin_cli::Destination::Stdout())
        .map_err(CarbideCliError::from)
}

pub async fn create(
    args: VpcPrefixCreate,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let output = do_create(api_client, args).await?;

    output
        .write_output(output_format, ::rpc::admin_cli::Destination::Stdout())
        .map_err(CarbideCliError::from)
}

pub async fn delete(args: VpcPrefixDelete, api_client: &ApiClient) -> CarbideCliResult<()> {
    do_delete(api_client, args).await
}

#[derive(Debug)]
enum ShowMethod {
    Get(VpcPrefixSelector),
    Search(VpcPrefixSearchQuery),
}

#[derive(Debug)]
enum ShowOutput {
    One(VpcPrefix),
    Many(Vec<VpcPrefix>),
}

impl ShowOutput {
    pub fn as_slice(&self) -> &[VpcPrefix] {
        match self {
            ShowOutput::One(vpc_prefix) => std::slice::from_ref(vpc_prefix),
            ShowOutput::Many(vpc_prefixes) => vpc_prefixes.as_slice(),
        }
    }
}

impl From<VpcPrefixShow> for ShowMethod {
    fn from(show_args: VpcPrefixShow) -> Self {
        match show_args.prefix_selector {
            Some(selector) => ShowMethod::Get(selector),
            None => {
                let mut search = match_all();
                search.vpc_id = show_args.vpc_id;
                if let Some(prefix) = &show_args.contains {
                    search.prefix_match_type = Some(PrefixMatchType::PrefixContains as i32);
                    search.prefix_match = Some(prefix.to_string());
                };
                if let Some(prefix) = &show_args.contained_by {
                    search.prefix_match_type = Some(PrefixMatchType::PrefixContainedBy as i32);
                    search.prefix_match = Some(prefix.to_string());
                };
                ShowMethod::Search(search)
            }
        }
    }
}

fn parse_label(s: &str) -> rpc::forge::Label {
    match s.split_once(':') {
        Some((k, v)) => rpc::forge::Label {
            key: k.trim().to_string(),
            value: Some(v.trim().to_string()),
        },
        None => rpc::forge::Label {
            key: s.trim().to_string(),
            value: None,
        },
    }
}

async fn do_create(
    api_client: &ApiClient,
    create_args: VpcPrefixCreate,
) -> Result<ShowOutput, CarbideCliError> {
    let labels = create_args
        .labels
        .unwrap_or_default()
        .iter()
        .map(|s| parse_label(s))
        .collect();

    let new_prefix = VpcPrefixCreationRequest {
        id: create_args.vpc_prefix_id,
        prefix: String::new(), // Deprecated field
        name: String::new(),   // Deprecated field
        vpc_id: Some(create_args.vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: create_args.prefix.to_string(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: create_args.name,
            labels,
            description: create_args.description.unwrap_or_default(),
        }),
    };

    api_client
        .0
        .create_vpc_prefix(new_prefix)
        .await
        .map(ShowOutput::One)
        .map_err(Into::into)
}

async fn do_delete(
    api_client: &ApiClient,
    delete_args: VpcPrefixDelete,
) -> Result<(), CarbideCliError> {
    let delete_prefix = VpcPrefixDeletionRequest {
        id: Some(delete_args.vpc_prefix_id),
    };
    api_client.0.delete_vpc_prefix(delete_prefix).await?;
    Ok(())
}

async fn fetch(
    api_client: &ApiClient,
    batch_size: usize,
    show_method: ShowMethod,
) -> Result<ShowOutput, CarbideCliError> {
    match show_method {
        ShowMethod::Get(get_one) => get_one.fetch(api_client).await.map(ShowOutput::One),
        ShowMethod::Search(query) => {
            let vpc_prefix_ids = search(api_client, query).await?;
            get_by_ids(api_client, batch_size, vpc_prefix_ids.as_slice())
                .await
                .map(ShowOutput::Many)
        }
    }
}

async fn search(
    api_client: &ApiClient,
    query: VpcPrefixSearchQuery,
) -> Result<Vec<VpcPrefixId>, CarbideCliError> {
    Ok(api_client
        .0
        .search_vpc_prefixes(query)
        .await
        .map(|response| response.vpc_prefix_ids)?)
}

async fn get_by_ids(
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

async fn get_one_by_id(
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

fn prefix_match_exact(prefix: &IpNet) -> rpc::forge::VpcPrefixSearchQuery {
    rpc::forge::VpcPrefixSearchQuery {
        prefix_match: Some(prefix.to_string()),
        prefix_match_type: Some(PrefixMatchType::PrefixExact as i32),
        ..Default::default()
    }
}

fn match_all() -> rpc::forge::VpcPrefixSearchQuery {
    rpc::forge::VpcPrefixSearchQuery {
        ..Default::default()
    }
}

enum Quantity<T> {
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

impl FormattedOutput for ShowOutput {}

impl Serialize for ShowOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ShowOutput::One(vpc_prefix) => vpc_prefix.serialize(serializer),
            ShowOutput::Many(vpc_prefixes) => vpc_prefixes.serialize(serializer),
        }
    }
}

impl IntoTable for ShowOutput {
    type Row = VpcPrefix;

    fn header(&self) -> &[&str] {
        &[
            "VpcPrefixId",
            "VpcId",
            "Prefix",
            "Name",
            "Total Linknets",
            "Available Linknets",
        ]
    }

    fn all_rows(&self) -> &[Self::Row] {
        self.as_slice()
    }

    fn row_values(row: &'_ Self::Row) -> Vec<Cow<'_, str>> {
        let vpc_prefix_id: Cow<str> = row.id.map(|id| id.to_string().into()).unwrap_or("".into());
        let vpc_id: Cow<str> = row
            .vpc_id
            .as_ref()
            .map(|id| id.to_string().into())
            .unwrap_or("".into());
        let prefix = row.prefix.as_str();
        let name = row.name.as_str();
        let mut r = vec![vpc_prefix_id, vpc_id, prefix.into(), name.into()];

        if let Some(status) = &row.status {
            r.push(status.total_linknet_segments.to_string().into());
            r.push(status.available_linknet_segments.to_string().into());
        } else {
            r.push("NA".into());
            r.push("NA".into());
        }

        r
    }
}
