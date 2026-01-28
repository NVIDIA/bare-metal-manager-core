/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use ::rpc::admin_cli::output::OutputFormat;
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::dpu_extension_service_credential::Type;
use ::rpc::forge::{
    DeleteDpuExtensionServiceRequest, DpuExtensionService, DpuExtensionServiceType,
    FindInstancesByDpuExtensionServiceRequest, GetDpuExtensionServiceVersionsInfoRequest,
    InstanceDpuExtensionServiceInfo,
};
use prettytable::{Table, row};

use super::args::{
    CreateExtensionService, DeleteExtensionService, GetExtensionServiceVersionInfo,
    ShowExtensionService, ShowExtensionServiceInstances, UpdateExtensionService,
};
use crate::rpc::ApiClient;

pub async fn handle_create(
    args: CreateExtensionService,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let credential =
        if args.username.is_some() || args.password.is_some() || args.registry_url.is_some() {
            // This check is for KubernetesPod service credentials, must be modified if we add more service types
            if args.username.is_none() || args.password.is_none() || args.registry_url.is_none() {
                return Err(CarbideCliError::GenericError(
                    "All of username, password and registry URL are required to create credential"
                        .to_string(),
                ));
            }

            Some(::rpc::forge::DpuExtensionServiceCredential {
                registry_url: args.registry_url.unwrap_or_default(),
                r#type: Some(Type::UsernamePassword(rpc::forge::UsernamePassword {
                    username: args.username.unwrap_or_default(),
                    password: args.password.unwrap_or_default(),
                })),
            })
        } else {
            None
        };

    let observability = if let Some(r) = args.observability {
        serde_json::from_str(&r)?
    } else {
        vec![]
    };

    let extension_service = api_client
        .create_extension_service(
            args.service_id,
            args.service_name,
            args.tenant_organization_id.unwrap_or_default(),
            args.service_type as i32,
            args.description,
            args.data,
            credential,
            observability,
        )
        .await?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&extension_service)?);
    } else {
        convert_extension_services_to_table(&[extension_service]).printstd();
    }

    Ok(())
}

pub async fn handle_update(
    args: UpdateExtensionService,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let credential =
        if args.username.is_some() || args.password.is_some() || args.registry_url.is_some() {
            if args.username.is_none() || args.password.is_none() || args.registry_url.is_none() {
                return Err(CarbideCliError::GenericError(
                    "All of username, password and registry URL are required to create credential"
                        .to_string(),
                ));
            }

            Some(::rpc::forge::DpuExtensionServiceCredential {
                registry_url: args.registry_url.unwrap(),
                r#type: Some(Type::UsernamePassword(rpc::forge::UsernamePassword {
                    username: args.username.unwrap(),
                    password: args.password.unwrap(),
                })),
            })
        } else {
            None
        };

    let observability = if let Some(r) = args.observability {
        serde_json::from_str(&r)?
    } else {
        vec![]
    };

    let extension_service = api_client
        .update_extension_service(
            args.service_id,
            args.service_name,
            args.description,
            args.data,
            credential,
            observability,
            args.if_version_ctr_match,
        )
        .await?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&extension_service)?);
    } else {
        convert_extension_services_to_table(&[extension_service]).printstd();
    }

    Ok(())
}

pub async fn handle_delete(
    args: DeleteExtensionService,
    _output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_dpu_extension_service(DeleteDpuExtensionServiceRequest {
            service_id: args.service_id,
            versions: args.versions,
        })
        .await?;

    println!("Delete successful");
    Ok(())
}

pub async fn handle_show(
    args: ShowExtensionService,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let services = if let Some(id) = args.id {
        let service = api_client.get_extension_service_by_id(id).await?;
        vec![service]
    } else {
        let service_list = api_client
            .find_extension_services(
                args.service_type.map(|t| t as i32),
                args.service_name,
                args.tenant_organization_id,
                page_size,
            )
            .await?;
        service_list.services
    };

    if is_json {
        println!("{}", serde_json::to_string_pretty(&services)?);
    } else {
        convert_extension_services_to_table(&services).printstd();
    }

    Ok(())
}

pub async fn handle_get_version(
    args: GetExtensionServiceVersionInfo,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let versions = api_client
        .0
        .get_dpu_extension_service_versions_info(GetDpuExtensionServiceVersionsInfoRequest {
            service_id: args.service_id,
            versions: args.versions,
        })
        .await?;

    println!("{}", serde_json::to_string_pretty(&versions.version_infos)?);

    Ok(())
}

pub async fn handle_show_instances(
    args: ShowExtensionServiceInstances,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let response = api_client
        .0
        .find_instances_by_dpu_extension_service(FindInstancesByDpuExtensionServiceRequest {
            service_id: args.service_id,
            version: args.version,
        })
        .await?;

    if is_json {
        let instances_json: Vec<serde_json::Value> = response
            .instances
            .iter()
            .map(|i| {
                serde_json::json!({
                    "instance_id": i.instance_id,
                    "service_id": i.service_id,
                    "version": i.version,
                    "removing": i.removed,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&instances_json)?);
    } else {
        convert_instances_to_table(&response.instances).printstd();
    }

    Ok(())
}

fn convert_extension_services_to_table(services: &[DpuExtensionService]) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Service ID",
        "Name",
        "Type",
        "Tenant Organization ID",
        "Version Counter",
        "Active Versions",
        "Description",
        "Created",
        "Updated",
    ]);

    for service in services {
        let service_type_name = DpuExtensionServiceType::try_from(service.service_type)
            .map(|t| t.as_str_name())
            .unwrap_or("Unknown");

        let active_versions = service.active_versions.join(", ");

        table.add_row(row![
            service.service_id,
            service.service_name,
            service_type_name,
            service.tenant_organization_id,
            service.version_ctr,
            active_versions,
            service.description,
            service.created,
            service.updated,
        ]);
    }

    table.into()
}

fn convert_instances_to_table(instances: &[InstanceDpuExtensionServiceInfo]) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Instance ID",
        "Service ID",
        "Version",
        "Config Status",
    ]);

    for instance in instances {
        let status = if instance.removed.is_some() {
            "Removing"
        } else {
            "Active"
        };

        table.add_row(row![
            instance.instance_id,
            instance.service_id,
            instance.version,
            status,
        ]);
    }

    table.into()
}
