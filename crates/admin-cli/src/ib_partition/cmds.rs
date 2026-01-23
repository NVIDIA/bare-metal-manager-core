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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use carbide_uuid::infiniband::IBPartitionId;
use prettytable::{Table, row};

use super::args::ShowIbPartition;
use crate::rpc::ApiClient;

pub async fn show(
    args: ShowIbPartition,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if let Some(id) = args.id {
        show_ib_partition_details(id, is_json, api_client).await?;
    } else {
        show_ib_partitions(
            is_json,
            api_client,
            page_size,
            args.tenant_org_id,
            args.name,
        )
        .await?;
    }
    Ok(())
}

async fn show_ib_partitions(
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let all_ib_partitions = match api_client
        .get_all_ib_partitions(tenant_org_id.clone(), name.clone(), page_size)
        .await
    {
        Ok(all_ib_partition_ids) => all_ib_partition_ids,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_ib_partitions)?);
    } else {
        convert_ib_partitions_to_nice_table(all_ib_partitions).printstd();
    }
    Ok(())
}

async fn show_ib_partition_details(
    id: IBPartitionId,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let ib_partitions = match api_client.get_one_ib_partition(id).await {
        Ok(instances) => instances,
        Err(e) => return Err(e),
    };

    if ib_partitions.ib_partitions.len() != 1 {
        return Err(CarbideCliError::GenericError(
            "Unknown InfiniBand Partition ID".to_string(),
        ));
    }

    let ib_partition = &ib_partitions.ib_partitions[0];

    if json {
        println!("{}", serde_json::to_string_pretty(ib_partition)?);
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
        (
            "ID",
            ib_partition.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
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
                    state_reason.outcome_msg.unwrap_or_default()
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
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    Ok(lines)
}
