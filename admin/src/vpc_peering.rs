/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use prettytable::{Table, row};

use crate::cfg::cli_options::{VpcPeeringCreate, VpcPeeringDelete, VpcPeeringShow};
use crate::rpc::ApiClient;
use rpc::forge::{VpcPeering, VpcPeeringIdList};
use utils::admin_cli::output::OutputFormat;
use utils::admin_cli::{CarbideCliError, CarbideCliResult};

pub async fn handle_create(
    args: VpcPeeringCreate,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let vpc_peering = match api_client
        .create_vpc_peering(Some(args.vpc1_id.into()), Some(args.vpc2_id.into()))
        .await
    {
        Ok(vpc_peering) => vpc_peering,
        Err(e) => return Err(e),
    };

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&vpc_peering).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_vpc_peerings_to_table(&[vpc_peering])?.printstd();
    }

    Ok(())
}

pub async fn handle_show(
    args: VpcPeeringShow,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let vpc_peering_ids = match (&args.id, &args.vpc_id) {
        (Some(id), None) => VpcPeeringIdList {
            vpc_peering_ids: vec![rpc::common::Uuid { value: id.into() }],
        },
        (None, _) => {
            let vpc_id = args.vpc_id.map(Into::into);
            api_client.find_vpc_peering_ids(vpc_id).await?
        }
        _ => unreachable!(
            "`--id` and `--vpc-id` are mutually exclusive and enforced by clap via `conflicts_with`"
        ),
    };

    let vpc_peering_list = api_client
        .find_vpc_peerings_by_ids(vpc_peering_ids.vpc_peering_ids)
        .await?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&vpc_peering_list).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_vpc_peerings_to_table(&vpc_peering_list.vpc_peerings)?.printstd();
    }

    Ok(())
}

pub async fn handle_delete(
    args: VpcPeeringDelete,
    _output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id = args.id.clone();
    api_client
        .delete_vpc_peering(Some(rpc::Uuid { value: args.id }))
        .await?;

    println!("Deleted VPC peering {} successfully", id);

    Ok(())
}

fn convert_vpc_peerings_to_table(vpc_peerings: &[VpcPeering]) -> CarbideCliResult<Box<Table>> {
    let mut table = Box::new(Table::new());

    table.set_titles(row!["Id", "VPC1 ID", "VPC2 ID"]);

    for vpc_peering in vpc_peerings {
        let id = vpc_peering
            .id
            .as_ref()
            .map(|id| id.value.as_str())
            .unwrap_or("");
        let vpc_id = vpc_peering
            .vpc_id
            .as_ref()
            .map(|uuid| uuid.to_string())
            .unwrap_or("None".to_string());
        let peer_vpc_id = vpc_peering
            .peer_vpc_id
            .as_ref()
            .map(|uuid| uuid.to_string())
            .unwrap_or("None".to_string());

        table.add_row(row![id, vpc_id, peer_vpc_id]);
    }

    Ok(table)
}
