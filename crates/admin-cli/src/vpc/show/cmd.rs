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
use std::borrow::Cow;
use std::fmt::Write;

use ::rpc::admin_cli::OutputFormat;
use ::rpc::forge::{self as forgerpc};
use carbide_uuid::vpc::VpcId;
use prettytable::{Table, row};

use super::args::Args;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

pub(crate) async fn show(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if let Some(id) = args.id {
        show_vpc_details(id, is_json, api_client).await?;
    } else {
        show_vpcs(
            is_json,
            api_client,
            page_size,
            args.tenant_org_id,
            args.name,
            args.label_key,
            args.label_value,
        )
        .await?;
    }
    Ok(())
}

async fn show_vpcs(
    json: bool,
    api_client: &ApiClient,
    page_size: usize,
    tenant_org_id: Option<String>,
    name: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<()> {
    let all_vpcs = match api_client
        .get_all_vpcs(tenant_org_id, name, page_size, label_key, label_value)
        .await
    {
        Ok(all_vpcs) => all_vpcs,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&all_vpcs)?);
    } else {
        convert_vpcs_to_nice_table(all_vpcs).printstd();
    }
    Ok(())
}

async fn show_vpc_details(
    vpc_id: VpcId,
    json: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let vpcs = api_client.0.find_vpcs_by_ids(vec![vpc_id]).await?;

    if vpcs.vpcs.len() != 1 {
        return Err(CarbideCliError::GenericError("Unknown VPC ID".to_string()));
    }

    let vpcs = &vpcs.vpcs[0];

    if json {
        println!("{}", serde_json::to_string_pretty(vpcs)?);
    } else {
        println!(
            "{}",
            convert_vpc_to_nice_format(vpcs).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

#[allow(deprecated)]
fn vpc_config(vpc: &forgerpc::Vpc) -> forgerpc::VpcConfig {
    if let Some(config) = vpc.config.clone() {
        config
    } else {
        forgerpc::VpcConfig {
            tenant_organization_id: vpc.tenant_organization_id.clone(),
            tenant_keyset_id: vpc.tenant_keyset_id.clone(),
            network_virtualization_type: vpc.network_virtualization_type,
            network_security_group_id: vpc.network_security_group_id.clone(),
            default_nvlink_logical_partition_id: vpc.default_nvlink_logical_partition_id,
            vni: vpc.vni,
            routing_profile_type: vpc.routing_profile_type.clone(),
            routing_profile_overrides: None,
            power_resource_group: None,
        }
    }
}

#[allow(deprecated)]
fn vpc_allocated_vni(vpc: &forgerpc::Vpc) -> u32 {
    vpc.status
        .as_ref()
        .and_then(|status| status.vni)
        .or(vpc.deprecated_vni)
        .unwrap_or_default()
}

#[allow(deprecated)]
fn vpc_virt_type(vpc: &forgerpc::Vpc) -> i32 {
    vpc_config(vpc)
        .network_virtualization_type
        .or(vpc.network_virtualization_type)
        .unwrap_or_default()
}

fn convert_vpcs_to_nice_table(vpcs: forgerpc::VpcList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "Name",
        "TenantOrg",
        "Network Security Group",
        "Version",
        "Created",
        "Virt Type",
        "Labels",
    ]);
    let default_metadata = Default::default();

    for vpc in vpcs.vpcs {
        let metadata = vpc.metadata.as_ref().unwrap_or(&default_metadata);
        let config = vpc_config(&vpc);
        let virt_type = forgerpc::VpcVirtualizationType::try_from(vpc_virt_type(&vpc))
            .unwrap_or_default()
            .as_str_name()
            .to_string();

        table.add_row(row![
            vpc.id.unwrap_or_default(),
            metadata.name,
            config.tenant_organization_id,
            config.network_security_group_id.unwrap_or_default(),
            vpc.version,
            vpc.created.unwrap_or_default(),
            virt_type,
            metadata
                .labels
                .iter()
                .map(|label| {
                    let key = &label.key;
                    let value = label.value.as_deref().unwrap_or_default();
                    format!("\"{key}:{value}\"")
                })
                .collect::<Vec<_>>()
                .join(", "),
        ]);
    }

    table.into()
}

#[allow(deprecated)]
pub(in crate::vpc) fn convert_vpc_to_nice_format(vpc: &forgerpc::Vpc) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();
    let config = vpc_config(vpc);
    let routing_profile_overrides = config
        .routing_profile_overrides
        .as_ref()
        .map(serde_json::to_string_pretty)
        .transpose()?
        .unwrap_or_else(|| "None".to_string());
    let effective_routing_profile = vpc
        .status
        .as_ref()
        .and_then(|status| status.effective_routing_profile.as_ref())
        .map(serde_json::to_string_pretty)
        .transpose()?
        .unwrap_or_else(|| "None".to_string());

    let vpc_name = vpc
        .metadata
        .as_ref()
        .map(|x| Cow::Borrowed(x.name.as_str()))
        .unwrap_or("<no name>".into());

    let data: Vec<(&'static str, Cow<str>)> = vec![
        ("ID", vpc.id.unwrap_or_default().to_string().into()),
        ("NAME", vpc_name),
        ("TENANT ORG", config.tenant_organization_id.as_str().into()),
        (
            "NETWORK SECURITY GROUP",
            config.network_security_group_id.unwrap_or_default().into(),
        ),
        ("VERSION", vpc.version.as_str().into()),
        (
            "CREATED",
            vpc.created.unwrap_or_default().to_string().into(),
        ),
        (
            "UPDATED",
            vpc.updated.unwrap_or_default().to_string().into(),
        ),
        (
            "DELETED",
            match vpc.deleted {
                Some(ts) => ts.to_string().into(),
                None => "".into(),
            },
        ),
        (
            "TENANT KEYSET",
            config.tenant_keyset_id.unwrap_or_default().into(),
        ),
        ("VNI", format!("{}", vpc_allocated_vni(vpc)).into()),
        (
            "NW VIRTUALIZATION",
            forgerpc::VpcVirtualizationType::try_from(vpc_virt_type(vpc))
                .unwrap_or_default()
                .as_str_name()
                .into(),
        ),
        (
            "ROUTING PROFILE TYPE",
            config.routing_profile_type.unwrap_or_default().into(),
        ),
        (
            "ROUTING PROFILE OVERRIDES",
            routing_profile_overrides.into(),
        ),
        (
            "EFFECTIVE ROUTING PROFILE",
            effective_routing_profile.into(),
        ),
    ];

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpc_details_include_routing_profiles() {
        let vpc = forgerpc::Vpc {
            config: Some(forgerpc::VpcConfig {
                tenant_organization_id: "tenant".to_string(),
                routing_profile_type: Some("INTERNAL".to_string()),
                routing_profile_overrides: Some(forgerpc::VpcRoutingProfileOverrides {
                    leak_default_route_from_underlay: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: Some(forgerpc::VpcStatus {
                effective_routing_profile: Some(forgerpc::VpcEffectiveRoutingProfile {
                    internal: true,
                    access_tier: 2,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let display = convert_vpc_to_nice_format(&vpc).expect("VPC display");
        assert!(display.contains("ROUTING PROFILE TYPE"));
        assert!(display.contains("INTERNAL"));
        let (_, routing_profiles) = display
            .split_once("ROUTING PROFILE OVERRIDES")
            .expect("routing-profile overrides");
        let (overrides, effective) = routing_profiles
            .split_once("EFFECTIVE ROUTING PROFILE")
            .expect("effective routing profile");
        assert!(overrides.contains("\"leak_default_route_from_underlay\": false"));
        assert!(!overrides.contains("\"internal\""));
        assert!(!overrides.contains("\"access_tier\""));
        assert!(effective.contains("\"internal\": true"));
        assert!(effective.contains("\"access_tier\": 2"));
    }
}
