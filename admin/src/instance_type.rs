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

use prettytable::{Table, row};
use rpc::forge::{
    CreateInstanceTypeRequest, DeleteInstanceTypeRequest, InstanceTypeAttributes,
    UpdateInstanceTypeRequest,
};

use super::CarbideCliError;

use crate::cfg::instance_type::{
    CreateInstanceType, DeleteInstanceType,
    ShowInstanceType, /*ShowInstanceTypeAssociations,*/
    UpdateInstanceType,
};
use crate::rpc::ApiClient;
use ::rpc::forge::{self as forgerpc, FindInstanceTypesByIdsRequest};
use utils::admin_cli::CarbideCliResult;
use utils::admin_cli::OutputFormat;

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
                let value = label.value.clone().unwrap_or_default();
                format!("\"{}:{}\"", key, value)
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
                .await
                .map_err(CarbideCliError::ApiInvocationError)?
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
        .await
        .map_err(CarbideCliError::ApiInvocationError)?
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
