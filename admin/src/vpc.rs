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

use super::cfg::carbide_options::ShowVpc;
use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::OutputFormat;
use crate::CarbideCliError;
use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};

pub async fn handle_show(
    args: ShowVpc,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.id.is_empty() {
        show_vpcs(
            is_json,
            api_config,
            page_size,
            args.tenant_org_id,
            args.name,
        )
        .await?;
        return Ok(());
    }
    show_vpc_details(args.id, is_json, api_config).await?;
    Ok(())
}

async fn show_vpcs(
    json: bool,
    api_config: &ApiConfig<'_>,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let all_vpc_ids = match rpc::get_vpc_ids(api_config, tenant_org_id.clone(), name.clone()).await
    {
        Ok(all_vpc_ids) => all_vpc_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            if tenant_org_id.is_some() {
                return Err(CarbideCliError::GenericError(
                    "Filtering by Tenant Org ID is not supported for this site.\
                \nIt does not have a required version of the Carbide API."
                        .to_string(),
                ));
            }
            return show_vpcs_deprecated(json, api_config, name).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_vpcs = forgerpc::VpcList {
        vpcs: Vec::with_capacity(all_vpc_ids.vpc_ids.len()),
    };
    for vpc_ids in all_vpc_ids.vpc_ids.chunks(page_size) {
        let vpcs = rpc::get_vpcs_by_ids(api_config, vpc_ids).await?;
        all_vpcs.vpcs.extend(vpcs.vpcs);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&all_vpcs).unwrap());
    } else {
        convert_vpcs_to_nice_table(all_vpcs).printstd();
    }
    Ok(())
}

async fn show_vpc_details(
    id: String,
    json: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let vpc_id: forgerpc::Uuid = uuid::Uuid::parse_str(&id)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let vpcs = match rpc::get_vpcs_by_ids(api_config, &[vpc_id.clone()]).await {
        Ok(instances) => instances,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            rpc::get_vpcs_deprecated(api_config, Some(vpc_id), None).await?
        }
        Err(e) => return Err(e),
    };

    if vpcs.vpcs.len() != 1 {
        return Err(CarbideCliError::GenericError("Unknown VPC ID".to_string()));
    }

    let vpcs = &vpcs.vpcs[0];

    if json {
        println!("{}", serde_json::to_string_pretty(vpcs).unwrap());
    } else {
        println!(
            "{}",
            convert_vpc_to_nice_format(vpcs).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

fn convert_vpcs_to_nice_table(vpcs: forgerpc::VpcList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "Name", "TenantOrg", "Version", "Created",]);

    for vpc in vpcs.vpcs {
        table.add_row(row![
            vpc.id.unwrap_or_default(),
            vpc.name,
            vpc.tenant_organization_id,
            vpc.version,
            vpc.created.unwrap_or_default(),
        ]);
    }

    table.into()
}

fn convert_vpc_to_nice_format(vpc: &forgerpc::Vpc) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let data = vec![
        ("ID", vpc.id.clone().unwrap_or_default().value),
        ("NAME", vpc.name.clone()),
        ("TENANT ORG", vpc.tenant_organization_id.clone()),
        ("VERSION", vpc.version.clone()),
        (
            "CREATED",
            vpc.created.clone().unwrap_or_default().to_string(),
        ),
        (
            "UPDATED",
            vpc.updated.clone().unwrap_or_default().to_string(),
        ),
        (
            "DELETED",
            match vpc.deleted.clone() {
                Some(ts) => ts.to_string(),
                None => "".to_string(),
            },
        ),
        (
            "TENANT KEYSET",
            vpc.tenant_keyset_id.clone().unwrap_or_default(),
        ),
        ("VNI", format!("{}", vpc.vni.unwrap_or_default())),
        (
            "NW VIRTUALIZATION",
            forgerpc::VpcVirtualizationType::try_from(
                vpc.network_virtualization_type.unwrap_or_default(),
            )
            .unwrap_or_default()
            .as_str_name()
            .to_string(),
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    Ok(lines)
}

// TODO: remove when all sites updated to carbide-api with get_vpc_ids and get_vpcs_by_ids implemented
async fn show_vpcs_deprecated(
    json: bool,
    api_config: &ApiConfig<'_>,
    name: Option<String>,
) -> CarbideCliResult<()> {
    let vpcs = rpc::get_vpcs_deprecated(api_config, None, name).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&vpcs).unwrap());
    } else {
        convert_vpcs_to_nice_table(vpcs).printstd();
    }
    Ok(())
}
