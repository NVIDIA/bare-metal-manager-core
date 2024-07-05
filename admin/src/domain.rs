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
use prettytable::{row, Table};
use std::fmt::Write;
use tracing::warn;

use super::cfg::carbide_options::{OutputFormat, ShowDomain};
use super::{rpc, CarbideCliError, CarbideCliResult};
use ::rpc::forge_tls_client::ApiConfig;
use ::rpc::{forge as forgerpc, Timestamp};

// timestamp_or_default returns a String representation of
// the given timestamp Option, or, if the Option is None,
// returns a String representation of the provided "default".
//
// A default is provided with the idea that multiple callers
// may want to use a default timestamp as part of a similar
// operation, and it would be strange for multiple sequential
// calls to get different timestamps.
//
// TODO(chet): Consider making default an &Option<Timestamp>,
// and if None, generate a default timestamp when called.
fn timestamp_or_default(ts: &Option<Timestamp>, default: &Timestamp) -> String {
    return ts.as_ref().unwrap_or(default).to_string();
}

fn convert_domain_to_nice_format(domain: &forgerpc::Domain) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let domain_default = &::rpc::common::Uuid::default();
    let timestamp_default = &Timestamp::default();

    let domain_id = domain.id.as_ref().unwrap_or(domain_default).value.as_str();
    let domain_created = timestamp_or_default(&domain.created, timestamp_default);
    let domain_updated = timestamp_or_default(&domain.updated, timestamp_default);
    let domain_deleted = timestamp_or_default(&domain.deleted, timestamp_default);

    let data = vec![
        ("ID", domain_id),
        ("NAME", domain.name.as_str()),
        ("CREATED", domain_created.as_str()),
        ("UPDATED", domain_updated.as_str()),
        ("DELETED", domain_deleted.as_str()),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    Ok(lines)
}

fn convert_domain_to_nice_table(domains: forgerpc::DomainList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "Name", "Created",]);

    for domain in domains.domains {
        table.add_row(row![
            domain.id.unwrap_or_default(),
            domain.name,
            domain.created.unwrap_or_default(),
        ]);
    }

    table.into()
}

async fn show_all_domains(json: bool, api_config: &ApiConfig<'_>) -> CarbideCliResult<()> {
    let domains = rpc::get_domains(None, api_config).await?;
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
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let domains = rpc::get_domains(
        Some(
            uuid::Uuid::parse_str(&id)
                .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
                .into(),
        ),
        api_config,
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
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.all || args.domain.is_empty() {
        show_all_domains(is_json, api_config).await?;
        // TODO(chet): Remove this ~March 2024.
        // Use tracing::warn for this so its both a little more
        // noticeable, and a little more annoying/naggy. If people
        // complain, it means its working.
        if args.all && output_format == OutputFormat::AsciiTable {
            warn!("redundant `--all` with basic `show` is deprecated. just do `domain show`.")
        }
        return Ok(());
    }
    show_domain_information(args.domain, is_json, api_config).await?;
    Ok(())
}
