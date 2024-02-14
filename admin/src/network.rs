/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::Write;

use ::rpc::forge as forgerpc;
use prettytable::{row, Table};
use serde::Deserialize;
use tracing::warn;

use super::cfg::carbide_options::{OutputFormat, ShowNetwork};
use super::{default_uuid, rpc, CarbideCliError, CarbideCliResult};
use crate::Config;

#[derive(Deserialize)]
struct NetworkState {
    state: String,
}

async fn convert_network_to_nice_format(
    segment: &forgerpc::NetworkSegment,
    api_config: Config,
) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let data = vec![
        ("ID", segment.id.clone().unwrap_or_default().value),
        ("NAME", segment.name.clone()),
        (
            "CREATED",
            segment.created.clone().unwrap_or_default().to_string(),
        ),
        (
            "UPDATED",
            segment.updated.clone().unwrap_or_default().to_string(),
        ),
        (
            "DELETED",
            segment
                .deleted
                .clone()
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
        (
            "DOMAIN",
            format!(
                "{}/{}",
                segment.subdomain_id.clone().unwrap_or_else(default_uuid),
                get_domain_name(segment.subdomain_id.clone(), api_config).await
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
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    writeln!(&mut lines, "{:<width$}: ", "PREFIXES")?;
    let width = 15;
    if segment.prefixes.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, prefix) in segment.prefixes.clone().into_iter().enumerate() {
            let data = vec![
                ("SN", i.to_string()),
                ("ID", prefix.id.clone().unwrap_or_default().to_string()),
                ("Prefix", prefix.prefix),
                (
                    "Gateway",
                    prefix
                        .gateway
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string())
                        .to_string(),
                ),
                ("Reserve First", prefix.reserve_first.to_string()),
                ("Circuit ID", prefix.circuit_id.unwrap_or_default()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
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
                x.time.clone().unwrap_or_default()
            )?;
        }
    }

    Ok(lines)
}

async fn get_domain_name(domain_id: Option<forgerpc::Uuid>, api_config: Config) -> String {
    match domain_id {
        Some(id) => match rpc::get_domains(Some(id), api_config).await {
            Ok(domain_list) => {
                if domain_list.domains.is_empty() {
                    return "Not Found in db".to_string();
                }

                domain_list.domains[0].name.clone()
            }
            Err(x) => x.to_string(),
        },
        None => "NA".to_owned(),
    }
}

async fn convert_network_to_nice_table(
    segments: forgerpc::NetworkSegmentList,
    api_config: Config,
) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "Name",
        "Created",
        "State",
        "Sub Domain",
        "MTU",
        "Prefixes",
        "Circuit Ids",
        "Version",
        "Type"
    ]);

    for segment in segments.network_segments {
        let domain = get_domain_name(segment.subdomain_id, api_config.clone()).await;

        table.add_row(row![
            segment.id.unwrap_or_default(),
            segment.name,
            segment.created.unwrap_or_default(),
            format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            ),
            domain,
            segment.mtu.unwrap_or(-1),
            segment
                .prefixes
                .iter()
                .map(|x| x.prefix.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            segment
                .prefixes
                .iter()
                .map(|x| x.circuit_id.clone().unwrap_or_else(|| "NA".to_owned()))
                .collect::<Vec<String>>()
                .join(", "),
            segment.version,
            format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(segment.segment_type).unwrap_or_default()
            ),
        ]);
    }

    table.into()
}

async fn show_all_segments(json: bool, api_config: Config) -> CarbideCliResult<()> {
    let segments = rpc::get_segments(None, api_config.clone()).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&segments).unwrap());
    } else {
        convert_network_to_nice_table(segments, api_config)
            .await
            .printstd();
    }
    Ok(())
}

async fn show_network_information(
    id: String,
    json: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    let segment = rpc::get_segments(
        Some(
            uuid::Uuid::parse_str(&id)
                .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
                .into(),
        ),
        api_config.clone(),
    )
    .await?;
    if segment.network_segments.is_empty() {
        return Err(CarbideCliError::SegmentNotFound);
    }
    let segment = &segment.network_segments[0];

    if json {
        println!("{}", serde_json::to_string_pretty(&segment).unwrap());
    } else {
        println!(
            "{}",
            convert_network_to_nice_format(segment, api_config)
                .await
                .unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowNetwork,
    output_format: OutputFormat,
    api_config: Config,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.all || args.network.is_empty() {
        show_all_segments(is_json, api_config).await?;
        // TODO(chet): Remove this ~March 2024.
        // Use tracing::warn for this so its both a little more
        // noticeable, and a little more annoying/naggy. If people
        // complain, it means its working.
        if args.all && output_format == OutputFormat::AsciiTable {
            warn!(
                "redundant `--all` with basic `show` is deprecated. just do `network-segment show`"
            )
        }
        return Ok(());
    }
    show_network_information(args.network, is_json, api_config).await?;
    Ok(())
}
