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
use std::fmt::Write;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc};
use carbide_uuid::vpc::VpcId;
use prettytable::{Table, row};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if let Some(id) = args.id {
        show_vpc_details(id, is_json, api_client).await?;
    } else {
        show_vpcs(
            is_json,
            api_client,
            page_size,
            args.tenant_org_id,
            args.name,
            args.label_key,
            args.label_value,
        )
        .await?;
    }
    Ok(())
}

async fn show_vpcs(
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<()> {
    let all_vpcs = match api_client
        .get_all_vpcs(tenant_org_id, name, page_size, label_key, label_value)
        .await
    {
        Ok(all_vpcs) => all_vpcs,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_vpcs)?);
    } else {
        convert_vpcs_to_nice_table(all_vpcs).printstd();
    }
    Ok(())
}

async fn show_vpc_details(
    vpc_id: VpcId,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let vpcs = api_client.0.find_vpcs_by_ids(vec![vpc_id]).await?;

    if vpcs.vpcs.len() != 1 {
        return Err(CarbideCliError::GenericError("Unknown VPC ID".to_string()));
    }

    let vpcs = &vpcs.vpcs[0];

    if json {
        println!("{}", serde_json::to_string_pretty(vpcs)?);
    } else {
        println!(
            "{}",
            convert_vpc_to_nice_format(vpcs).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

fn convert_vpcs_to_nice_table(vpcs: forgerpc::VpcList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "Name",
        "TenantOrg",
        "Network Security Group",
        "Version",
        "Created",
        "Virt Type",
        "Labels",
    ]);
    let default_metadata = Default::default();

    for vpc in vpcs.vpcs {
        let metadata = vpc.metadata.as_ref().unwrap_or(&default_metadata);
        let virt_type = forgerpc::VpcVirtualizationType::try_from(
            vpc.network_virtualization_type.unwrap_or_default(),
        )
        .unwrap_or_default()
        .as_str_name()
        .to_string();

        table.add_row(row![
            vpc.id.unwrap_or_default(),
            vpc.name,
            vpc.tenant_organization_id,
            vpc.network_security_group_id.unwrap_or_default(),
            vpc.version,
            vpc.created.unwrap_or_default(),
            virt_type,
            metadata
                .labels
                .iter()
                .map(|label| {
                    let key = &label.key;
                    let value = label.value.as_deref().unwrap_or_default();
                    format!("\"{key}:{value}\"")
                })
                .collect::<Vec<_>>()
                .join(", "),
        ]);
    }

    table.into()
}

fn convert_vpc_to_nice_format(vpc: &forgerpc::Vpc) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let data: Vec<(&'static str, Cow<str>)> = vec![
        ("ID", vpc.id.unwrap_or_default().to_string().into()),
        ("NAME", vpc.name.as_str().into()),
        ("TENANT ORG", vpc.tenant_organization_id.as_str().into()),
        (
            "NETWORK SECURITY GROUP",
            vpc.network_security_group_id().into(),
        ),
        ("VERSION", vpc.version.as_str().into()),
        (
            "CREATED",
            vpc.created.unwrap_or_default().to_string().into(),
        ),
        (
            "UPDATED",
            vpc.updated.unwrap_or_default().to_string().into(),
        ),
        (
            "DELETED",
            match vpc.deleted {
                Some(ts) => ts.to_string().into(),
                None => "".into(),
            },
        ),
        ("TENANT KEYSET", vpc.tenant_keyset_id().into()),
        (
            "VNI",
            format!("{}", vpc.status.and_then(|s| s.vni).unwrap_or_default()).into(),
        ),
        (
            "NW VIRTUALIZATION",
            forgerpc::VpcVirtualizationType::try_from(
                vpc.network_virtualization_type.unwrap_or_default(),
            )
            .unwrap_or_default()
            .as_str_name()
            .into(),
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    Ok(lines)
}
