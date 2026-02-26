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
use std::fmt::Write;
use std::str::FromStr as _;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use carbide_uuid::domain::DomainId;
use carbide_uuid::network::NetworkSegmentId;
use prettytable::{Table, row};
use serde::Deserialize;

use super::args::Args;
use crate::rpc::ApiClient;

#[derive(Deserialize)]
struct NetworkState {
    state: String,
}

async fn convert_network_to_nice_format(
    segment: forgerpc::NetworkSegment,
    api_client: &ApiClient,
) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let data = vec![
        (
            "ID",
            segment.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        ("NAME", segment.name),
        ("CREATED", segment.created.unwrap_or_default().to_string()),
        ("UPDATED", segment.updated.unwrap_or_default().to_string()),
        (
            "DELETED",
            segment
                .deleted
                .map(|x| x.to_string())
                .unwrap_or("Not Deleted".to_string()),
        ),
        (
            "STATE",
            format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            ),
        ),
        ("VPC", segment.vpc_id.unwrap_or_default().to_string()),
        (
            "DOMAIN",
            format!(
                "{}/{}",
                segment.subdomain_id.unwrap_or_default(),
                get_domain_name(segment.subdomain_id, api_client).await
            ),
        ),
        (
            "TYPE",
            format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(segment.segment_type).unwrap_or_default()
            ),
        ),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    writeln!(&mut lines, "{:<width$}: ", "PREFIXES")?;
    let width = 15;
    if segment.prefixes.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, prefix) in segment.prefixes.into_iter().enumerate() {
            let net = ipnet::IpNet::from_str(&prefix.prefix).unwrap();
            let range = format!("{} - {}", net.network(), net.broadcast());
            let data = vec![
                ("SN", i.to_string()),
                ("ID", prefix.id.unwrap_or_default().to_string()),
                ("Prefix", prefix.prefix),
                ("Range", range),
                (
                    "Gateway",
                    prefix.gateway.unwrap_or_else(|| "Unknown".to_string()),
                ),
                ("SVI IP", prefix.svi_ip.unwrap_or_default()),
                ("Reserve First", prefix.reserve_first.to_string()),
                ("Free IP Count", prefix.free_ip_count.to_string()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t------------------------------------------------------------"
            )?;
        }
    }

    writeln!(&mut lines, "STATE HISTORY: (Latest 5 only)")?;
    if segment.history.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        writeln!(
            &mut lines,
            "\tState          Version                      Time"
        )?;
        writeln!(
            &mut lines,
            "\t---------------------------------------------------"
        )?;
        for x in segment.history.iter().rev().take(5).rev() {
            writeln!(
                &mut lines,
                "\t{:<15} {:25} {}",
                serde_json::from_str::<NetworkState>(&x.state)?.state,
                x.version,
                x.time.unwrap_or_default()
            )?;
        }
    }

    Ok(lines)
}

async fn get_domain_name(domain_id: Option<DomainId>, api_client: &ApiClient) -> String {
    match domain_id {
        Some(id) => match api_client.get_domains(Some(id)).await {
            Ok(domain_list) => {
                let Some(first) = domain_list.domains.into_iter().next() else {
                    return "Not Found in db".to_string();
                };

                first.name
            }
            Err(x) => x.to_string(),
        },
        None => "NA".to_owned(),
    }
}

fn convert_network_to_nice_table(segments: forgerpc::NetworkSegmentList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id", "Name", "Created", "State", "Vpc ID", "MTU", "Prefixes", "Last IP", "Version",
        "Type",
    ]);

    for segment in segments.network_segments {
        let net = ipnet::IpNet::from_str(&segment.prefixes.first().unwrap().prefix).unwrap();
        let end_ip = net.broadcast().to_string();

        table.add_row(row![
            segment.id.unwrap_or_default(),
            segment.name,
            segment.created.unwrap_or_default(),
            format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            ),
            segment.vpc_id.unwrap_or_default(),
            segment.mtu.unwrap_or(-1),
            segment
                .prefixes
                .iter()
                .map(|x| x.prefix.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            end_ip,
            segment.version,
            format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(segment.segment_type).unwrap_or_default()
            ),
        ]);
    }

    table.into()
}

async fn show_all_segments(
    json: bool,
    api_client: &ApiClient,
    tenant_org_id: Option<String>,
    name: Option<String>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let all_segments = match api_client
        .get_all_segments(tenant_org_id, name, page_size)
        .await
    {
        Ok(all_segment_ids) => all_segment_ids,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_segments)?);
    } else {
        convert_network_to_nice_table(all_segments).printstd();
    }
    Ok(())
}

async fn show_network_information(
    segment_id: NetworkSegmentId,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let segment = match api_client.get_one_segment(segment_id).await {
        Ok(instances) => instances,
        Err(e) => return Err(e),
    };

    let Some(segment) = segment.network_segments.into_iter().next() else {
        return Err(CarbideCliError::SegmentNotFound);
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&segment)?);
    } else {
        println!(
            "{}",
            convert_network_to_nice_format(segment, api_client)
                .await
                .unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if let Some(network) = args.network {
        show_network_information(network, is_json, api_client).await?;
    } else {
        show_all_segments(
            is_json,
            api_client,
            args.tenant_org_id,
            args.name,
            page_size,
        )
        .await?;
    }
    Ok(())
}
