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
use std::collections::HashMap;
use std::fmt::Write;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use carbide_uuid::nvlink::{NvLinkLogicalPartitionId, NvLinkPartitionId};
use prettytable::{Table, row};

use super::args::{
    CreateLogicalPartition, DeleteLogicalPartition, ShowLogicalPartition, ShowNvlPartition,
};
use crate::rpc::ApiClient;

pub async fn handle_show_physical_partitions(
    args: ShowNvlPartition,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.id.is_empty() {
        show_nvl_physical_partitions(
            is_json,
            api_client,
            page_size,
            args.tenant_org_id,
            args.name,
        )
        .await?;
        return Ok(());
    }
    show_nvl_physical_partition_details(args.id, is_json, api_client, page_size).await?;
    Ok(())
}

async fn show_nvl_physical_partitions(
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let all_nvl_partitions = api_client
        .get_all_nv_link_partitions(tenant_org_id, name, page_size)
        .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&all_nvl_partitions)?);
    } else {
        convert_nvl_physical_partitions_to_nice_table(all_nvl_partitions).printstd();
    }
    Ok(())
}

async fn show_nvl_physical_partition_details(
    id: String,
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let nvl_partition_id: NvLinkPartitionId = uuid::Uuid::parse_str(&id)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let nvl_partition = api_client
        .get_one_nv_link_partition(nvl_partition_id)
        .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&nvl_partition)?);
    } else {
        println!(
            "{}",
            convert_nvl_physical_partition_to_nice_format(nvl_partition)
                .unwrap_or_else(|x| x.to_string())
        );
        let member_map = fetch_partition_gpu_members(api_client, page_size).await?;
        if let Some(gpus) = member_map.get(&nvl_partition_id)
            && !gpus.is_empty()
        {
            println!("\nGPUs:");
            gpu_members_table(gpus).printstd();
        }
    }
    Ok(())
}

fn convert_nvl_physical_partitions_to_nice_table(
    nvl_partitions: forgerpc::NvLinkPartitionList,
) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "Name", "TenantOrg"]);

    for nvl_partition in nvl_partitions.partitions {
        table.add_row(row![
            nvl_partition.id.unwrap_or_default(),
            nvl_partition.name,
        ]);
    }

    table.into()
}

fn gpu_members_table(gpus: &[(String, String)]) -> Box<Table> {
    let mut table = Table::new();
    table.set_titles(row!["Machine ID", "GPU GUID"]);
    for (machine_id, gpu_guid) in gpus {
        table.add_row(row![machine_id, gpu_guid]);
    }
    table.into()
}

fn convert_nvl_physical_partition_to_nice_format(
    nvl_partition: forgerpc::NvLinkPartition,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let data = vec![
        ("ID", nvl_partition.id.unwrap_or_default().to_string()),
        ("NAME", nvl_partition.name),
        (
            "LOGICAL PARTITION ID",
            nvl_partition
                .logical_partition_id
                .map(|logical_partition_id| logical_partition_id.to_string())
                .unwrap_or_default(),
        ),
        ("NMX-M-ID", nvl_partition.nmx_m_id),
        (
            "NVLINK DOMAIN UUID",
            nvl_partition.domain_uuid.unwrap_or_default().to_string(),
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    Ok(lines)
}

/// Build a map from NvLink partition_id to list of (machine_id, gpu_guid) by fetching
/// machines with mnnvl_only and scanning NvLinkGpuStatusObservation (mirrors api web nvlink.rs).
async fn fetch_partition_gpu_members(
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<HashMap<NvLinkPartitionId, Vec<(String, String)>>> {
    let request = forgerpc::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_predicted_host: false,
        only_maintenance: false,
        exclude_hosts: false,
        only_quarantine: false,
        instance_type_id: None,
        mnnvl_only: true,
    };
    let machines = api_client.get_all_machines(request, page_size).await?;
    let mut member_map: HashMap<NvLinkPartitionId, Vec<(String, String)>> = HashMap::new();
    for m in machines.machines {
        if let Some(ref status) = m.nvlink_status_observation {
            for gpu in &status.gpu_status {
                if let Some(ref partition_id) = gpu.partition_id {
                    member_map.entry(*partition_id).or_default().push((
                        m.id.as_ref().map(|id| id.to_string()).unwrap_or_default(),
                        gpu.guid.to_string(),
                    ));
                }
            }
        }
    }
    Ok(member_map)
}

pub async fn handle_show_logical_partitions(
    args: ShowLogicalPartition,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.id.is_empty() {
        show_all_logical_partitions(is_json, api_client, page_size, args.name).await?;
        return Ok(());
    }
    show_logical_partition_details(args.id, is_json, api_client, page_size).await?;
    Ok(())
}

async fn show_all_logical_partitions(
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let all_logical_partitions = match api_client.get_all_logical_partitions(name, page_size).await
    {
        Ok(all_logical_partition_ids) => all_logical_partition_ids,
        Err(e) => return Err(e),
    };
    let physical_partition_counts: HashMap<NvLinkLogicalPartitionId, usize> = if json {
        HashMap::new()
    } else {
        let all_nv_link = api_client
            .get_all_nv_link_partitions(None, None, page_size)
            .await?;
        all_nv_link
            .partitions
            .into_iter()
            .filter_map(|p| p.logical_partition_id)
            .fold(HashMap::new(), |mut m, id| {
                *m.entry(id).or_insert(0) += 1;
                m
            })
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_logical_partitions)?);
    } else {
        convert_partitions_to_nice_table(all_logical_partitions, physical_partition_counts)
            .printstd();
    }
    Ok(())
}

async fn show_logical_partition_details(
    id: String,
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let partition_id: NvLinkLogicalPartitionId = uuid::Uuid::parse_str(&id)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let logical_partition = api_client.get_one_logical_partition(partition_id).await?;

    let all_nv_link_partitions = api_client
        .get_all_nv_link_partitions(None, None, page_size)
        .await?;
    let matching_partitions: Vec<forgerpc::NvLinkPartition> = all_nv_link_partitions
        .partitions
        .into_iter()
        .filter(|p| p.logical_partition_id.as_ref() == Some(&partition_id))
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&logical_partition)?);
        println!(
            "{}",
            serde_json::to_string_pretty(&forgerpc::NvLinkPartitionList {
                partitions: matching_partitions,
            })?
        );
    } else {
        println!(
            "{}",
            convert_partition_to_nice_format(&logical_partition).unwrap_or_else(|x| x.to_string())
        );
        if !matching_partitions.is_empty() {
            println!("\nPhysical NvLink Partitions:");
            convert_nvl_partitions_to_table(matching_partitions).printstd();
        }
    }
    Ok(())
}

fn convert_nvl_partitions_to_table(partitions: Vec<forgerpc::NvLinkPartition>) -> Box<Table> {
    let mut table = Table::new();
    table.set_titles(row!["Id", "Name"]);
    for p in partitions {
        table.add_row(row![p.id.unwrap_or_default(), p.name.clone()]);
    }
    table.into()
}

fn convert_partitions_to_nice_table(
    partitions: forgerpc::NvLinkLogicalPartitionList,
    physical_partition_counts: HashMap<NvLinkLogicalPartitionId, usize>,
) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "State", "Created", "Physical Partitions"]);

    for partition in partitions.partitions {
        let count = partition
            .id
            .as_ref()
            .and_then(|id| physical_partition_counts.get(id).copied())
            .unwrap_or(0);
        table.add_row(row![
            partition.id.unwrap_or_default(),
            forgerpc::TenantState::try_from(partition.status.unwrap_or_default().state,)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
            partition
                .created
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_default(),
            count,
        ]);
    }

    table.into()
}

fn convert_partition_to_nice_format(
    partition: &forgerpc::NvLinkLogicalPartition,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let _status = partition.status.unwrap_or_default();
    let data = vec![
        (
            "ID",
            partition
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
        ),
        (
            "NAME",
            partition
                .config
                .clone()
                .unwrap_or_default()
                .metadata
                .unwrap_or_default()
                .name,
        ),
        (
            "STATUS",
            forgerpc::TenantState::try_from(partition.status.unwrap_or_default().state)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
        ),
        (
            "CREATED",
            partition
                .created
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_default(),
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    Ok(lines)
}

// The following create and delete functions are only for debug during development
pub async fn handle_logical_partition_create(
    args: CreateLogicalPartition,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    create_logical_partition(args, api_client).await?;
    Ok(())
}

pub async fn handle_logical_partition_delete(
    args: DeleteLogicalPartition,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    delete_logical_partition(args, api_client).await?;
    Ok(())
}

pub async fn create_logical_partition(
    args: CreateLogicalPartition,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let metadata = forgerpc::Metadata {
        name: args.name,
        labels: vec![forgerpc::Label {
            key: "cloud-unsafe-op".to_string(),
            value: Some("true".to_string()),
        }],
        ..Default::default()
    };
    let request = forgerpc::NvLinkLogicalPartitionCreationRequest {
        config: Some(forgerpc::NvLinkLogicalPartitionConfig {
            metadata: Some(metadata),
            tenant_organization_id: args.tenant_organization_id,
        }),
        id: None,
    };
    let _partition = api_client
        .0
        .create_nv_link_logical_partition(request)
        .await?;
    Ok(())
}

pub async fn delete_logical_partition(
    args: DeleteLogicalPartition,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let uuid: NvLinkLogicalPartitionId = uuid::Uuid::parse_str(&args.name)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let request = forgerpc::NvLinkLogicalPartitionDeletionRequest { id: Some(uuid) };
    let _partition = api_client
        .0
        .delete_nv_link_logical_partition(request)
        .await?;
    Ok(())
}
