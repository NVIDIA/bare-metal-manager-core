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
use super::cfg::carbide_options::ShowDomain;
use super::{rpc, CarbideCliError, CarbideCliResult};
use ::rpc::forge as forgerpc;
use prettytable::{row, Table};
use std::fmt::Write;

fn convert_domain_to_nice_format(domain: &forgerpc::Domain) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let data = vec![
        ("ID", domain.id.clone().unwrap_or_default().value),
        ("NAME", domain.name.clone()),
        (
            "CREATED",
            domain.created.clone().unwrap_or_default().to_string(),
        ),
        (
            "UPDATED",
            domain.updated.clone().unwrap_or_default().to_string(),
        ),
        (
            "DELETED",
            domain.deleted.clone().unwrap_or_default().to_string(),
        ),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    Ok(lines)
}

fn convert_domain_to_nice_table(domains: forgerpc::DomainList) -> Box<Table> {
    let mut table = Table::new();

    table.add_row(row!["Id", "Name", "Created",]);

    for domain in domains.domains {
        table.add_row(row![
            domain.id.unwrap_or_default(),
            domain.name,
            domain.created.unwrap_or_default(),
        ]);
    }

    table.into()
}

async fn show_all_domains(json: bool, carbide_api: String) -> CarbideCliResult<()> {
    let domains = rpc::get_domains(None, carbide_api.clone()).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&domains).unwrap());
    } else {
        convert_domain_to_nice_table(domains).printstd();
    }
    Ok(())
}

async fn show_domain_information(
    id: String,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    let domains = rpc::get_domains(
        Some(
            uuid::Uuid::parse_str(&id)
                .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
                .into(),
        ),
        carbide_api.clone(),
    )
    .await?;
    if domains.domains.is_empty() {
        return Err(CarbideCliError::DomainNotFound);
    }
    let domain = &domains.domains[0];

    if json {
        println!("{}", serde_json::to_string_pretty(&domain).unwrap());
    } else {
        println!(
            "{}",
            convert_domain_to_nice_format(domain).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowDomain,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    if args.all {
        show_all_domains(json, carbide_api).await?;
    } else if let Some(uuid) = args.uuid {
        show_domain_information(uuid, json, carbide_api).await?;
    }

    Ok(())
}
