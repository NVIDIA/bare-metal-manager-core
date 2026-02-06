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
use carbide_uuid::machine::MachineId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Create an instance type", visible_alias = "c")]
    Create(CreateInstanceType),

    #[clap(about = "Show one or more instance types", visible_alias = "s")]
    Show(ShowInstanceType),

    #[clap(about = "Delete an instance type", visible_alias = "d")]
    Delete(DeleteInstanceType),

    #[clap(about = "Update an instance type", visible_alias = "u")]
    Update(UpdateInstanceType),

    #[clap(
        about = "Associate an instance type with machines",
        visible_alias = "a"
    )]
    Associate(AssociateInstanceType),

    #[clap(
        about = "Remove an instance type association from a machines",
        visible_alias = "r"
    )]
    Disassociate(DisassociateInstanceType),
}

#[derive(Parser, Debug, Clone)]
pub struct AssociateInstanceType {
    #[clap(help = "InstanceTypeId")]
    pub instance_type_id: String,
    #[clap(help = "Machine Ids, separated by comma", value_delimiter = ',')]
    pub machine_ids: Vec<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DisassociateInstanceType {
    #[clap(help = "Machine Id")]
    pub machine_id: MachineId,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateInstanceType {
    #[clap(
        short = 'i',
        long,
        help = "Optional, unique ID to use when creating the instance type"
    )]
    pub id: Option<String>,

    #[clap(short = 'n', long, help = "Name of the instance type")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the instance type")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the instance type"
    )]
    pub labels: Option<String>,

    #[clap(
        short = 'f',
        long,
        help = "Optional, JSON array containing a set of instance type capability filters"
    )]
    pub desired_capabilities: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ShowInstanceType {
    #[clap(
        short = 'i',
        long,
        help = "Optional, instance type ID to restrict the search"
    )]
    pub id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ShowInstanceTypeAssociations {
    #[clap(short = 'i', long, help = "instance type ID to query")]
    pub id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateInstanceType {
    #[clap(short = 'i', long, help = "Instance type ID to update")]
    pub id: String,

    #[clap(short = 'n', long, help = "Name of the instance type")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the instance type")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the instance type - will COMPLETELY overwrite any existing labels"
    )]
    pub labels: Option<String>,

    #[clap(
        short = 'f',
        long,
        help = "Optional, JSON array containing a set of instance type capability filters - will COMPLETELY overwrite any existing filters"
    )]
    pub desired_capabilities: Option<String>,

    #[clap(
        short = 'v',
        long,
        help = "Optional, version to use for comparison when performing the update, which will be rejected if the actual version of the record does not match the value of this parameter"
    )]
    pub version: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteInstanceType {
    #[clap(short = 'i', long, help = "Instance type ID to delete")]
    pub id: String,
}
