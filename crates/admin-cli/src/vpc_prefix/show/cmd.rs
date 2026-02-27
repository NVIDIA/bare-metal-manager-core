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

use ::rpc::admin_cli::output::{FormattedOutput, IntoTable, OutputFormat};
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use rpc::forge::{PrefixMatchType, VpcPrefix};
use serde::Serialize;

use super::args::Args;
use crate::rpc::ApiClient;
use crate::vpc_prefix::common::{VpcPrefixSelector, get_by_ids, match_all, search};

pub async fn show(
    args: Args,
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

#[derive(Debug)]
enum ShowMethod {
    Get(VpcPrefixSelector),
    Search(rpc::forge::VpcPrefixSearchQuery),
}

pub enum ShowOutput {
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

impl From<Args> for ShowMethod {
    fn from(show_args: Args) -> Self {
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
