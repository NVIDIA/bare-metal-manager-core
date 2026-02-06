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

use std::collections::HashSet;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc, DeleteNetworkSecurityGroupRequest};
use prettytable::{Table, row};

use super::args::{
    AttachNetworkSecurityGroup, CreateNetworkSecurityGroup, DeleteNetworkSecurityGroup,
    DetachNetworkSecurityGroup, ShowNetworkSecurityGroup, ShowNetworkSecurityGroupAttachments,
    UpdateNetworkSecurityGroup,
};
use crate::rpc::ApiClient;

/// Produces a table for printing a non-JSON representation of a
/// network security group to standard out.
///
/// * `nsgs`    - A reference to an active DB transaction
/// * `verbose` - A bool to select more verbose output (e.g., include full rule details)
fn convert_nsgs_to_table(
    nsgs: &[forgerpc::NetworkSecurityGroup],
    verbose: bool,
) -> CarbideCliResult<Box<Table>> {
    let mut table = Box::new(Table::new());
    let default_metadata = Default::default();

    if verbose {
        table.set_titles(row![
            "Id",
            "Tenant Organization ID",
            "Name",
            "Description",
            "Version",
            "Created",
            "Created By",
            "Updated By",
            "Labels",
            "Stateful Egress",
            "Rules"
        ]);
    } else {
        table.set_titles(row![
            "Id",
            "Tenant Organization ID",
            "Name",
            "Description",
            "Version",
            "Created",
            "Created By",
            "Updated By",
            "Labels",
        ]);
    }

    for nsg in nsgs {
        let metadata = nsg.metadata.as_ref().unwrap_or(&default_metadata);

        let labels = metadata
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.as_deref().unwrap_or_default();
                format!("\"{key}:{value}\"")
            })
            .collect::<Vec<_>>();

        let default_attributes = forgerpc::NetworkSecurityGroupAttributes {
            stateful_egress: false,
            rules: vec![],
        };

        if verbose {
            table.add_row(row![
                nsg.id,
                nsg.tenant_organization_id,
                metadata.name,
                metadata.description,
                nsg.version,
                nsg.created_at(),
                nsg.created_by(),
                nsg.updated_by(),
                labels.join(", "),
                nsg.attributes
                    .as_ref()
                    .unwrap_or(&default_attributes)
                    .stateful_egress,
                serde_json::to_string_pretty(
                    &nsg.attributes.as_ref().unwrap_or(&default_attributes).rules
                )
                .map_err(CarbideCliError::JsonError)?,
            ]);
        } else {
            table.add_row(row![
                nsg.id,
                nsg.tenant_organization_id,
                metadata.name,
                metadata.description,
                nsg.version,
                nsg.created_at(),
                nsg.created_by(),
                nsg.updated_by(),
                labels.join(", "),
            ]);
        }
    }

    Ok(table)
}

/// Show one or more NSGs.
/// If only a single NSG is found, verbose output is used
/// automatically.
pub async fn show(
    args: ShowNetworkSecurityGroup,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
    verbose: bool,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let mut nsgs = Vec::new();
    if let Some(id) = args.id {
        let nsg = api_client.get_single_network_security_group(id).await?;
        nsgs.push(nsg);
    } else {
        nsgs = api_client
            .get_all_network_security_groups(page_size)
            .await?;
    }

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&nsgs).map_err(CarbideCliError::JsonError)?
        );
    } else if nsgs.len() == 1 {
        convert_nsgs_to_table(&nsgs, true)?.printstd();
    } else {
        convert_nsgs_to_table(&nsgs, verbose)?.printstd();
    }

    Ok(())
}

/// Delete a network security group.
pub async fn delete(
    args: DeleteNetworkSecurityGroup,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_network_security_group(DeleteNetworkSecurityGroupRequest {
            id: args.id.clone(),
            tenant_organization_id: args.tenant_organization_id,
        })
        .await?;
    println!("Deleted network security group {} successfully.", args.id);
    Ok(())
}

/// Update a network security group.
/// On successful update, the details of the
/// group will be displayed.
pub async fn update(
    args: UpdateNetworkSecurityGroup,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let id = args.id;

    let nsg = api_client
        .get_single_network_security_group(id.clone())
        .await?;

    let mut metadata = nsg.metadata.unwrap_or_default();
    let (mut rules, mut stateful_egress) = {
        let nsg = nsg.attributes.unwrap_or_default();
        (nsg.rules, nsg.stateful_egress)
    };

    if let Some(d) = args.description {
        metadata.description = d;
    }

    if let Some(n) = args.name {
        metadata.name = n;
    }

    if let Some(l) = args.labels {
        metadata.labels = serde_json::from_str(&l)?;
    }

    if let Some(r) = args.rules {
        rules = serde_json::from_str(&r)?;
    }

    if let Some(s) = args.stateful_egress {
        stateful_egress = s;
    }

    let nsg = api_client
        .update_network_security_group(
            id,
            args.tenant_organization_id,
            metadata,
            args.version,
            stateful_egress,
            rules,
        )
        .await?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&nsg).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_nsgs_to_table(&[nsg], true)?.printstd();
    }

    Ok(())
}

/// Create a network security group.
/// On successful creation, the details of the
/// new group will be displayed.
pub async fn create(
    args: CreateNetworkSecurityGroup,
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

    let rules = if let Some(r) = args.rules {
        serde_json::from_str(&r)?
    } else {
        vec![]
    };

    let nsg = api_client
        .create_network_security_group(
            id,
            args.tenant_organization_id,
            metadata,
            args.stateful_egress,
            rules,
        )
        .await?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&nsg).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_nsgs_to_table(&[nsg], true)?.printstd();
    }

    Ok(())
}

/// Display details about objects that are using the
/// requested NSG, including propagation status of the
/// NSG across that object
pub async fn show_attachments(
    args: ShowNetworkSecurityGroupAttachments,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    // Grab the NSG details.
    let nsg = api_client
        .get_single_network_security_group(args.id.clone())
        .await?;

    // Grab the list of IDs for objects that are directly using this NSG.
    let nsg_attachments = api_client
        .get_network_security_group_attachments(args.id.clone())
        .await?;

    if nsg_attachments.vpc_ids.is_empty() && nsg_attachments.instance_ids.is_empty() {
        println!(
            "Network security group {} is not referenced by any objects",
            args.id.clone()
        );

        return Ok(());
    }

    // Next, prepare some sugar for users by grabbing the
    // propagation details for all objects using the NSG.
    let (vpcs, instances) = api_client
        .get_network_security_group_propagation_status(
            args.id.clone(),
            Some(nsg_attachments.vpc_ids.clone()),
            Some(nsg_attachments.instance_ids.clone()),
        )
        .await?;

    if is_json {
        // JSON output will get simple details.
        println!(
            "{{\"network_security_group\": {}, \"attachments\": {}, \"vpc_propagation_status\": {}, \"instance_propagation_status\": {}}}",
            serde_json::to_string_pretty(&nsg).map_err(CarbideCliError::JsonError)?,
            serde_json::to_string_pretty(&nsg_attachments).map_err(CarbideCliError::JsonError)?,
            serde_json::to_string_pretty(&vpcs).map_err(CarbideCliError::JsonError)?,
            serde_json::to_string_pretty(&instances).map_err(CarbideCliError::JsonError)?,
        );
    } else {
        let mut attachments_table = Box::new(Table::new());
        let mut propagation_table = Box::new(Table::new());

        attachments_table.set_titles(row!["Id", "Type"]);
        propagation_table.set_titles(row!["Id", "Type", "Relationship", "Propagated",]);

        for instance in nsg_attachments.instance_ids {
            attachments_table.add_row(row![instance, "INSTANCE",]);
        }

        for vpc in nsg_attachments.vpc_ids {
            attachments_table.add_row(row![vpc, "VPC",]);
        }

        for instance in instances {
            propagation_table.add_row(row![
                instance.id,
                "INSTANCE",
                "DIRECT",
                instance.status().as_str_name()
            ]);
        }

        for vpc in vpcs {
            propagation_table.add_row(row![vpc.id, "VPC", "DIRECT", vpc.status().as_str_name()]);

            let mut id_set = HashSet::<String>::new();

            // If the user wants to see an extended view
            // we can show them some details about objects
            // that are directly using the NSG _and_ objects
            // that are inheriting rules because a parent object
            // is a using the NSG.
            if args.include_indirect {
                for id in vpc.unpropagated_instance_ids {
                    id_set.insert(id);
                }

                for id in vpc.related_instance_ids {
                    // If it was seen already, then it's not propagated.
                    if id_set.contains(&id) {
                        propagation_table.add_row(row![
                            id,
                            "INSTANCE",
                            format!("INDIRECT via VPC {}", vpc.id),
                            forgerpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone
                                .as_str_name()
                        ]);
                    } else {
                        propagation_table.add_row(row![
                            id,
                            "INSTANCE",
                            format!("INDIRECT via VPC {}", vpc.id),
                            forgerpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull
                                .as_str_name()
                        ]);
                    }
                }
            }
        }

        convert_nsgs_to_table(&[nsg], false)?.printstd();
        println!("\nAttachments:");
        attachments_table.printstd();
        println!("\nPropagation:");
        propagation_table.printstd();
    }

    Ok(())
}

/// "Attaches" a network security group to an object (VPC/Instance)
/// by updating the config of the object.
pub async fn attach(
    args: AttachNetworkSecurityGroup,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    // Check that at least one of instance ID or VPC ID has been sent
    if args.instance_id.is_none() && args.vpc_id.is_none() {
        return Err(CarbideCliError::GenericError(
            "one of instance ID or VPC ID must be used".to_string(),
        ));
    }

    // Grab the instance for the ID if requested.
    if let Some(instance_id) = args.instance_id {
        let instance = api_client
            .get_one_instance(instance_id)
            .await?
            .instances
            .pop()
            .ok_or(CarbideCliError::UuidNotFound)?;

        // Grab the instance config for the target instance.
        // We'll modify the NSG ID field and then resubmit.
        let Some(mut config) = instance.config else {
            return Err(CarbideCliError::GenericError(
                "requested instance found without config".to_string(),
            ));
        };

        // Set the nsg ID
        config.network_security_group_id = Some(args.id.clone());

        // Resubmit the data back to the system.
        let _instance = api_client
            .update_instance_config(
                instance_id,
                instance.config_version,
                config,
                instance.metadata,
            )
            .await?;

        println!(
            "Network security group {} successfully attached to instance {}",
            args.id.clone(),
            instance_id
        );
    }

    // Grab the VPC for the ID if requested.
    if let Some(v) = args.vpc_id {
        let vpc = api_client
            .0
            .find_vpcs_by_ids(&[v])
            .await?
            .vpcs
            .pop()
            .ok_or(CarbideCliError::UuidNotFound)?;

        // Submit the VPC details back to the system but change the
        // NSG ID value.
        let _vpc = api_client
            .update_vpc_config(
                v,
                vpc.version,
                vpc.name,
                vpc.metadata,
                Some(args.id.clone()),
            )
            .await?;

        println!(
            "Network security group {} successfully attached to VPC {}",
            args.id.clone(),
            v
        );
    }

    Ok(())
}

/// "Detaches" a network security group to an object (VPC/Instance)
/// by updating the config of the object.
pub async fn detach(
    args: DetachNetworkSecurityGroup,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    // Check that at least one of instance ID or VPC ID has been sent
    if args.instance_id.is_none() && args.vpc_id.is_none() {
        return Err(CarbideCliError::GenericError(
            "one of instance ID or VPC ID must be used".to_string(),
        ));
    }

    // Grab the instance for the ID if requested.
    if let Some(instance_id) = args.instance_id {
        let instance = api_client
            .get_one_instance(instance_id)
            .await?
            .instances
            .pop()
            .ok_or(CarbideCliError::UuidNotFound)?;

        // Similar to attachment, we'll grab the full config
        // so we can empty the NSG ID field and then resubmit.
        let Some(mut config) = instance.config else {
            return Err(CarbideCliError::GenericError(
                "requested instance found without config".to_string(),
            ));
        };

        // Clear the NSD ID field.
        config.network_security_group_id = None;

        // Submit the config to the system.
        let _instance = api_client
            .update_instance_config(
                instance_id,
                instance.config_version,
                config,
                instance.metadata,
            )
            .await?;

        println!("Network security group successfully detached from instance {instance_id}");
    }

    // Grab the instance for the ID if requested.
    if let Some(v) = args.vpc_id {
        let vpc = api_client
            .0
            .find_vpcs_by_ids(&[v])
            .await?
            .vpcs
            .pop()
            .ok_or(CarbideCliError::UuidNotFound)?;

        // Similar to attachment, we'll resubmit the
        // VPC details we just grabbed and only clear
        // the NSG ID field.
        let _vpc = api_client
            .update_vpc_config(v, vpc.version, vpc.name, vpc.metadata, None)
            .await?;

        println!("Network security group successfully detached from VPC {v}");
    }

    Ok(())
}
