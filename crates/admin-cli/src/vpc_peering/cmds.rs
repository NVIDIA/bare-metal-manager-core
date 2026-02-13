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

use ::rpc::admin_cli::output::OutputFormat;
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use prettytable::{Table, row};
use rpc::forge::{
    VpcPeering, VpcPeeringCreationRequest, VpcPeeringIdList, VpcPeeringSearchFilter,
    VpcPeeringsByIdsRequest,
};

use super::args::{CreateVpcPeering, DeleteVpcPeering, ShowVpcPeering};
use crate::rpc::ApiClient;

pub async fn create(
    args: &CreateVpcPeering,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let vpc_peering = api_client
        .0
        .create_vpc_peering(VpcPeeringCreationRequest {
            vpc_id: Some(args.vpc1_id),
            peer_vpc_id: Some(args.vpc2_id),
            id: args.id,
        })
        .await?;

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

pub async fn show(
    args: &ShowVpcPeering,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let vpc_peering_ids = match (&args.id, &args.vpc_id) {
        (Some(id), None) => VpcPeeringIdList {
            vpc_peering_ids: vec![*id],
        },
        (None, _) => {
            api_client
                .0
                .find_vpc_peering_ids(VpcPeeringSearchFilter {
                    vpc_id: args.vpc_id,
                })
                .await?
        }
        _ => unreachable!(
            "`--id` and `--vpc-id` are mutually exclusive and enforced by clap via `conflicts_with`"
        ),
    };

    let vpc_peering_list = api_client
        .0
        .find_vpc_peerings_by_ids(VpcPeeringsByIdsRequest {
            vpc_peering_ids: vpc_peering_ids.vpc_peering_ids,
        })
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

pub async fn delete(
    args: &DeleteVpcPeering,
    _output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client.0.delete_vpc_peering(args.id).await?;
    println!("Deleted VPC peering {} successfully", args.id);
    Ok(())
}

fn convert_vpc_peerings_to_table(vpc_peerings: &[VpcPeering]) -> CarbideCliResult<Box<Table>> {
    let mut table = Box::new(Table::new());

    table.set_titles(row!["Id", "VPC1 ID", "VPC2 ID"]);

    for vpc_peering in vpc_peerings {
        let id = vpc_peering.id.map(|id| id.to_string()).unwrap_or_default();
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
