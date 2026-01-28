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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc, FindInstanceTypesByIdsRequest};
use carbide_uuid::machine::MachineId;
use prettytable::{Table, row};
use rpc::TenantState;
use rpc::forge::{
    AssociateMachinesWithInstanceTypeRequest, CreateInstanceTypeRequest, DeleteInstanceTypeRequest,
    InstanceTypeAttributes, RemoveMachineInstanceTypeAssociationRequest, UpdateInstanceTypeRequest,
};

use super::args::{
    AssociateInstanceType, CreateInstanceType, DeleteInstanceType, DisassociateInstanceType,
    ShowInstanceType, UpdateInstanceType,
};
use crate::rpc::ApiClient;

/// Produces a table for printing a non-JSON representation of a
/// instance type to standard out.
///
/// * `itypes`  - A reference to an active DB transaction
/// * `verbose` - A bool to select more verbose output (e.g., include full rule details)
fn convert_itypes_to_table(
    itypes: &[forgerpc::InstanceType],
    verbose: bool,
) -> CarbideCliResult<Box<Table>> {
    let mut table = Box::new(Table::new());
    let default_metadata = Default::default();

    if verbose {
        table.set_titles(row![
            "Id",
            "Name",
            "Description",
            "Version",
            "Created",
            "Labels",
            "Filters"
        ]);
    } else {
        table.set_titles(row![
            "Id",
            "Name",
            "Description",
            "Version",
            "Created",
            "Labels",
        ]);
    }

    for itype in itypes {
        let metadata = itype.metadata.as_ref().unwrap_or(&default_metadata);

        let labels = metadata
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.as_deref().unwrap_or_default();
                format!("\"{key}:{value}\"")
            })
            .collect::<Vec<_>>();

        let default_attributes = forgerpc::InstanceTypeAttributes {
            desired_capabilities: vec![],
        };

        if verbose {
            table.add_row(row![
                itype.id,
                metadata.name,
                metadata.description,
                itype.version,
                itype.created_at(),
                labels.join(", "),
                serde_json::to_string_pretty(
                    &itype
                        .attributes
                        .as_ref()
                        .unwrap_or(&default_attributes)
                        .desired_capabilities
                )
                .map_err(CarbideCliError::JsonError)?,
            ]);
        } else {
            table.add_row(row![
                itype.id,
                metadata.name,
                metadata.description,
                itype.version,
                itype.created_at(),
                labels.join(", "),
            ]);
        }
    }

    Ok(table)
}

/// Show one or more InstanceTypes.
/// If only a single InstanceType is found, verbose output is used
/// automatically.
pub async fn show(
    args: ShowInstanceType,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
    verbose: bool,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let itypes = if let Some(id) = args.id {
        vec![
            api_client
                .0
                .find_instance_types_by_ids(FindInstanceTypesByIdsRequest {
                    instance_type_ids: vec![id],
                })
                .await?
                .instance_types
                .pop()
                .ok_or(CarbideCliError::Empty)?,
        ]
    } else {
        api_client.get_all_instance_types(page_size).await?
    };

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&itypes).map_err(CarbideCliError::JsonError)?
        );
    } else if itypes.len() == 1 {
        convert_itypes_to_table(&itypes, true)?.printstd();
    } else {
        convert_itypes_to_table(&itypes, verbose)?.printstd();
    }

    Ok(())
}

/// Delete an instance type.
pub async fn delete(args: DeleteInstanceType, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_instance_type(DeleteInstanceTypeRequest {
            id: args.id.clone(),
        })
        .await?;
    println!("Deleted instance type {} successfully.", args.id);
    Ok(())
}

/// Update an instance type.
/// On successful update, the details of the
/// type will be displayed.
pub async fn update(
    args: UpdateInstanceType,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let id = args.id;

    let itype = api_client
        .0
        .find_instance_types_by_ids(FindInstanceTypesByIdsRequest {
            instance_type_ids: vec![id.clone()],
        })
        .await?
        .instance_types
        .pop()
        .ok_or(CarbideCliError::Empty)?;

    let mut metadata = itype.metadata.unwrap_or_default();

    if let Some(d) = args.description {
        metadata.description = d;
    }

    if let Some(n) = args.name {
        metadata.name = n;
    }

    if let Some(l) = args.labels {
        metadata.labels = serde_json::from_str(&l)?;
    }

    let instance_type_attributes = args
        .desired_capabilities
        .map(|d| {
            serde_json::from_str(&d).map(|desired_capabilities| InstanceTypeAttributes {
                desired_capabilities,
            })
        })
        .transpose()?;

    let itype = api_client
        .0
        .update_instance_type(UpdateInstanceTypeRequest {
            id,
            metadata: Some(metadata),
            if_version_match: args.version,
            instance_type_attributes,
        })
        .await?
        .instance_type
        .ok_or(CarbideCliError::Empty)?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&itype).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_itypes_to_table(&[itype], true)?.printstd();
    }

    Ok(())
}

/// Create an instance type.
/// On successful creation, the details of the
/// new type will be displayed.
pub async fn create(
    args: CreateInstanceType,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let id = args.id;

    let labels = if let Some(l) = args.labels {
        serde_json::from_str(&l)?
    } else {
        vec![]
    };

    let metadata = forgerpc::Metadata {
        name: args.name.unwrap_or_default(),
        description: args.description.unwrap_or_default(),
        labels,
    };

    let instance_type_attributes = args
        .desired_capabilities
        .map(|d| {
            serde_json::from_str(&d).map(|desired_capabilities| InstanceTypeAttributes {
                desired_capabilities,
            })
        })
        .transpose()?;

    let itype = api_client
        .0
        .create_instance_type(CreateInstanceTypeRequest {
            id,
            metadata: Some(metadata),
            instance_type_attributes,
        })
        .await?
        .instance_type
        .ok_or(CarbideCliError::Empty)?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&itype).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_itypes_to_table(&[itype], true)?.printstd();
    }

    Ok(())
}

pub async fn create_association(
    associate_instance_type: AssociateInstanceType,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    if associate_instance_type.machine_ids.is_empty() {
        return Err(CarbideCliError::GenericError(
            "Machine ids can not be empty.".to_string(),
        ));
    }

    api_client
        .0
        .associate_machines_with_instance_type(AssociateMachinesWithInstanceTypeRequest {
            instance_type_id: associate_instance_type.instance_type_id,
            machine_ids: associate_instance_type.machine_ids,
        })
        .await?;

    println!("Association is created successfully!!");

    Ok(())
}

pub async fn remove_association(
    disassociate_instance_type: DisassociateInstanceType,
    cloud_unsafe_operation_allowed: bool,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let instance = api_client
        .0
        .find_instance_by_machine_id(disassociate_instance_type.machine_id)
        .await?;

    if let Some(instance) = instance.instances.first() {
        if let Some(status) = &instance.status
            && let Some(tenant) = &status.tenant
        {
            match tenant.state() {
                TenantState::Terminating | TenantState::Terminated => {
                    if !cloud_unsafe_operation_allowed {
                        return Err(CarbideCliError::GenericError(
                                r#"A instance is already allocated to this machine, but terminating.
        Removing instance type will create a mismatch between cloud and carbide. If you are sure, run this command again with --cloud-unsafe-op=<username> flag before `instance-type`."#.to_string(),
        ));
                    }
                    remove_association_api(api_client, disassociate_instance_type.machine_id)
                        .await?;
                    return Ok(());
                }
                _ => {}
            }
        }
        return Err(CarbideCliError::GenericError(
            "A instance is already allocated to this machine. You can remove an instance-type association only in Teminating state.".to_string(),
        ));
    } else {
        remove_association_api(api_client, disassociate_instance_type.machine_id).await?;
    }

    Ok(())
}

async fn remove_association_api(
    api_client: &ApiClient,
    machine_id: MachineId,
) -> Result<(), CarbideCliError> {
    api_client
        .0
        .remove_machine_instance_type_association(RemoveMachineInstanceTypeAssociationRequest {
            machine_id: machine_id.to_string(),
        })
        .await?;
    println!("Association is removed successfully!!");
    Ok(())
}
