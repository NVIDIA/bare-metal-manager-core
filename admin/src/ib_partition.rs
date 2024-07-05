/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use super::cfg::carbide_options::ShowIbPartition;
use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::OutputFormat;
use crate::CarbideCliError;
use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};

pub async fn handle_show(
    args: ShowIbPartition,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.id.is_empty() {
        show_ib_partitions(
            is_json,
            api_config,
            page_size,
            args.tenant_org_id,
            args.name,
        )
        .await?;
        return Ok(());
    }
    show_ib_partition_details(args.id, is_json, api_config).await?;
    Ok(())
}

async fn show_ib_partitions(
    json: bool,
    api_config: &ApiConfig<'_>,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let all_ib_partition_ids =
        match rpc::get_ib_partition_ids(api_config, tenant_org_id.clone(), name.clone()).await {
            Ok(all_ib_partition_ids) => all_ib_partition_ids,
            Err(CarbideCliError::ApiInvocationError(status))
                if status.code() == tonic::Code::Unimplemented =>
            {
                if tenant_org_id.is_some() || name.is_some() {
                    return Err(CarbideCliError::GenericError(
                        "Filtering by Tenant Org ID or Name is not supported for this site.\
                \nIt does not have a required version of the Carbide API."
                            .to_string(),
                    ));
                }
                return show_ib_partitions_deprecated(json, api_config).await;
            }
            Err(e) => return Err(e),
        };
    let mut all_ib_partitions = forgerpc::IbPartitionList {
        ib_partitions: Vec::with_capacity(all_ib_partition_ids.ib_partition_ids.len()),
    };
    for ids in all_ib_partition_ids.ib_partition_ids.chunks(page_size) {
        let ib_partitions = rpc::get_ib_partitions_by_ids(api_config, ids).await?;
        all_ib_partitions
            .ib_partitions
            .extend(ib_partitions.ib_partitions);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&all_ib_partitions).unwrap()
        );
    } else {
        convert_ib_partitions_to_nice_table(all_ib_partitions).printstd();
    }
    Ok(())
}

async fn show_ib_partition_details(
    id: String,
    json: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let ib_partition_id: ::rpc::common::Uuid = uuid::Uuid::parse_str(&id)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let ib_partitions =
        match rpc::get_ib_partitions_by_ids(api_config, &[ib_partition_id.clone()]).await {
            Ok(instances) => instances,
            Err(CarbideCliError::ApiInvocationError(status))
                if status.code() == tonic::Code::Unimplemented =>
            {
                rpc::get_ib_partitions_deprecated(api_config, Some(ib_partition_id)).await?
            }
            Err(e) => return Err(e),
        };

    if ib_partitions.ib_partitions.len() != 1 {
        return Err(CarbideCliError::GenericError(
            "Unknown InfiniBand Partition ID".to_string(),
        ));
    }

    let ib_partition = &ib_partitions.ib_partitions[0];

    if json {
        println!("{}", serde_json::to_string_pretty(ib_partition).unwrap());
    } else {
        println!(
            "{}",
            convert_ib_partition_to_nice_format(ib_partition).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

fn convert_ib_partitions_to_nice_table(ib_partitions: forgerpc::IbPartitionList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "Name", "TenantOrg", "State", "Pkey",]);

    for ib_partition in ib_partitions.ib_partitions {
        table.add_row(row![
            ib_partition.id.unwrap_or_default(),
            ib_partition.config.clone().unwrap_or_default().name,
            ib_partition
                .config
                .unwrap_or_default()
                .tenant_organization_id,
            forgerpc::TenantState::try_from(ib_partition.status.clone().unwrap_or_default().state,)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
            ib_partition
                .status
                .clone()
                .unwrap_or_default()
                .pkey
                .unwrap_or_default(),
        ]);
    }

    table.into()
}

fn convert_ib_partition_to_nice_format(
    ib_partition: &forgerpc::IbPartition,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let config = ib_partition.config.clone().unwrap_or_default();
    let status = ib_partition.status.clone().unwrap_or_default();
    let state_reason = status.state_reason.unwrap_or_default();
    let data = vec![
        ("ID", ib_partition.id.clone().unwrap_or_default().value),
        ("NAME", config.name),
        ("TENANT ORG", config.tenant_organization_id),
        (
            "STATE",
            forgerpc::TenantState::try_from(status.state)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
        ),
        (
            "STATE MACHINE",
            match forgerpc::ControllerStateOutcome::try_from(state_reason.outcome)
                .unwrap_or_default()
            {
                forgerpc::ControllerStateOutcome::Transition
                | forgerpc::ControllerStateOutcome::DoNothing
                | forgerpc::ControllerStateOutcome::Todo => "OK".to_string(),
                forgerpc::ControllerStateOutcome::Wait
                | forgerpc::ControllerStateOutcome::Error => {
                    state_reason.outcome_msg.clone().unwrap_or_default()
                }
            },
        ),
        ("PKEY", status.pkey.unwrap_or_default()),
        ("PARTITION", status.partition.unwrap_or_default()),
        (
            "SERVICE LEVEL",
            format!("{}", status.service_level.unwrap_or_default()),
        ),
        ("RATE", format!("{}", status.rate_limit.unwrap_or_default())),
        ("MTU", format!("{}", status.mtu.unwrap_or_default())),
        (
            "SHARP APPS",
            if status.enable_sharp.unwrap_or_default() {
                "YES".to_string()
            } else {
                "NO".to_string()
            },
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    Ok(lines)
}

// TODO: remove when all sites updated to carbide-api with get_ib_partition_ids and get_ib_partitions_by_ids implemented
async fn show_ib_partitions_deprecated(
    json: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let ib_partitions = rpc::get_ib_partitions_deprecated(api_config, None).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&ib_partitions).unwrap());
    } else {
        convert_ib_partitions_to_nice_table(ib_partitions).printstd();
    }
    Ok(())
}
