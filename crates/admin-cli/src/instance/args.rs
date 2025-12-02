/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::vpc::VpcPrefixId;
use clap::{ArgGroup, Parser};
use rpc::InstanceInfinibandConfig;
use rpc::forge::{InstanceNvLinkConfig, OperatingSystem};

use crate::cfg::cli_options::SortField;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display instance information")]
    Show(ShowInstance),
    #[clap(about = "Reboot instance, potentially applying firmware updates")]
    Reboot(RebootInstance),
    #[clap(about = "De-allocate instance")]
    Release(ReleaseInstance),
    #[clap(about = "Allocate instance")]
    Allocate(AllocateInstance),
    #[clap(about = "Update instance OS")]
    UpdateOS(UpdateInstanceOS),
    #[clap(about = "Update instance IB configuration")]
    UpdateIbConfig(UpdateIbConfig),
    #[clap(about = "Update instance NVLink configuration")]
    UpdateNvLinkConfig(UpdateNvLinkConfig),
}

/// ShowInstance is used for `cli instance show` configuration,
/// with the ability to filter by a combination of labels, tenant
/// org ID, and VPC ID.
//
// TODO: Possibly add the ability to filter by a list of tenant
// org IDs and/or VPC IDs.
#[derive(Parser, Debug)]
pub struct ShowInstance {
    #[clap(
        default_value(""),
        help = "The instance ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub extrainfo: bool,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC ID to query.")]
    pub vpc_id: Option<String>,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,

    #[clap(long, help = "The instance type ID to query.")]
    pub instance_type_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct RebootInstance {
    #[clap(short, long)]
    pub instance: InstanceId,

    #[clap(short, long, action)]
    pub custom_pxe: bool,

    #[clap(short, long, action)]
    pub apply_updates_on_reboot: bool,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("release_instance")
        .required(true)
        .args(&["instance", "machine", "label_key"])))]
pub struct ReleaseInstance {
    #[clap(short, long)]
    pub instance: Option<String>,

    #[clap(short, long)]
    pub machine: Option<MachineId>,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("selector").required(true).args(&["subnet", "vpc_prefix_id"])))]
pub struct AllocateInstance {
    #[clap(short, long)]
    pub number: Option<u16>,

    #[clap(short, long, help = "The subnet to assign to a PF")]
    pub subnet: Vec<String>,

    #[clap(short, long, help = "The VPC prefix to assign to a PF")]
    pub vpc_prefix_id: Vec<VpcPrefixId>,

    #[clap(short, long)]
    // This will not be needed after vpc_prefix implementation.
    // Code can query to carbide and fetch it from db using vpc_prefix_id.
    pub tenant_org: Option<String>,

    #[clap(short, long, required = true)]
    pub prefix_name: String,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,

    #[clap(
        long,
        help = "The ID of a network security group to apply to the new instance upon creation"
    )]
    pub network_security_group_id: Option<String>,

    #[clap(
        long,
        help = "The expected instance type id for the instance, which will be compared to type ID set for the machine of the request"
    )]
    pub instance_type_id: Option<String>,

    #[clap(long, help = "OS definition in JSON format", value_name = "OS_JSON")]
    pub os: Option<OperatingSystem>,

    #[clap(long, help = "The subnet to assign to a VF")]
    pub vf_subnet: Vec<String>,

    #[clap(long, help = "The VPC prefix to assign to a VF")]
    pub vf_vpc_prefix_id: Vec<VpcPrefixId>,

    #[clap(
        long,
        help = "The machine ids for the machines to use (instead of searching)"
    )]
    pub machine_id: Vec<MachineId>,

    #[clap(
        long,
        help = "Use batch API for all-or-nothing allocation (requires --number > 1)"
    )]
    pub transactional: bool,
}

#[derive(Parser, Debug)]
pub struct UpdateInstanceOS {
    #[clap(short, long, required(true))]
    pub instance: InstanceId,
    #[clap(
        long,
        required(true),
        help = "OS definition in JSON format",
        value_name = "OS_JSON"
    )]
    pub os: OperatingSystem,
}

#[derive(Parser, Debug)]
pub struct UpdateIbConfig {
    #[clap(short, long, required(true))]
    pub instance: InstanceId,
    #[clap(
        long,
        required(true),
        help = "IB configuration in JSON format",
        value_name = "IB_JSON"
    )]
    pub config: InstanceInfinibandConfig,
}

#[derive(Parser, Debug)]
pub struct UpdateNvLinkConfig {
    #[clap(short, long, required(true))]
    pub instance: InstanceId,
    #[clap(
        long,
        required(true),
        help = "NVLink configuration in JSON format",
        value_name = "NVLINK_JSON"
    )]
    pub config: InstanceNvLinkConfig,
}

/// Global options passed to instance commands
pub struct GlobalOptions<'a> {
    pub format: rpc::admin_cli::OutputFormat,
    pub page_size: usize,
    pub sort_by: &'a SortField,
    pub cloud_unsafe_op: Option<String>,
}
