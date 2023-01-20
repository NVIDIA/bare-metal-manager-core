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
use super::cfg::carbide_options::ShowNetwork;
use super::{default_uuid, rpc, CarbideCliError, CarbideCliResult};
use ::rpc::forge as forgerpc;
use prettytable::{row, Table};
use std::fmt::Write;

async fn convert_network_to_nice_format(
    segment: &forgerpc::NetworkSegment,
    carbide_api: String,
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
            "STATE",
            format!(
                "{:?}",
                forgerpc::TenantState::from_i32(segment.state).unwrap_or_default()
            ),
        ),
        (
            "DOMAIN",
            format!(
                "{}/{}",
                segment.subdomain_id.clone().unwrap_or_else(default_uuid),
                get_domain_name(segment.subdomain_id.clone(), carbide_api).await
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
                (
                    "State",
                    prefix.state.map(|x| x.state).unwrap_or_default().to_owned(),
                ),
                ("Circuit ID", prefix.circuit_id.unwrap_or_default()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    Ok(lines)
}

async fn get_domain_name(domain_id: Option<forgerpc::Uuid>, carbide_api: String) -> String {
    match domain_id {
        Some(id) => match rpc::get_domains(Some(id), carbide_api.clone()).await {
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
    carbide_api: String,
) -> String {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "Name",
        "Created",
        "State",
        "Sub Domain",
        "MTU",
        "Prefixes",
        "Circuit Ids",
        "Version"
    ]);

    for segment in segments.network_segments {
        let domain = get_domain_name(segment.subdomain_id, carbide_api.clone()).await;

        table.add_row(row![
            segment.id.unwrap_or_default(),
            segment.name,
            segment.created.unwrap_or_default(),
            format!(
                "{:?}",
                forgerpc::TenantState::from_i32(segment.state).unwrap_or_default()
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
        ]);
    }

    table.to_string()
}

async fn show_all_segments(json: bool, carbide_api: String) -> CarbideCliResult<()> {
    let segments = rpc::get_segments(None, carbide_api.clone()).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&segments).unwrap());
    } else {
        println!(
            "{}",
            convert_network_to_nice_table(segments, carbide_api).await
        );
    }
    Ok(())
}

async fn show_network_information(
    id: String,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    let segment = rpc::get_segments(
        Some(
            uuid::Uuid::parse_str(&id)
                .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
                .into(),
        ),
        carbide_api.clone(),
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
            convert_network_to_nice_format(segment, carbide_api)
                .await
                .unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowNetwork,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    if args.all {
        show_all_segments(json, carbide_api).await?;
    } else if let Some(uuid) = args.uuid {
        show_network_information(uuid, json, carbide_api).await?;
    }

    Ok(())
}
