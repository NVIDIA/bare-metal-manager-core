/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::{ArgGroup, Parser};
use mac_address::MacAddress;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Retrieves the latest site exploration report", subcommand)]
    GetReport(GetReportMode),
    #[clap(
        about = "Asks carbide-api to explore a single host and prints the report. Does not store it."
    )]
    Explore(ExploreOptions),
    #[clap(
        about = "Asks carbide-api to explore a single host in the next exploration cycle. The results will be stored."
    )]
    ReExplore(ReExploreOptions),
    #[clap(about = "Clear the last known error for the BMC in the latest site exploration report.")]
    ClearError(ExploreOptions),
    #[clap(about = "Delete an explored endpoint from the database.")]
    Delete(DeleteExploredEndpointOptions),
    #[clap(about = "Control remediation actions for an explored endpoint.")]
    Remediation(RemediationOptions),
    IsBmcInManagedHost(ExploreOptions),
    HaveCredentials(ExploreOptions),
    CopyBfbToDpuRshim(CopyBfbToDpuRshimArgs),
}

#[derive(Parser, Debug, PartialEq)]
pub enum GetReportMode {
    #[clap(about = "Get everything in Json")]
    All,
    #[clap(about = "Get discovered host details.")]
    ManagedHost(ManagedHostInfo),
    #[clap(about = "Get Endpoint details.")]
    Endpoint(EndpointInfo),
}

#[derive(Parser, Debug, PartialEq)]
#[clap(group(ArgGroup::new("selector").required(false).args(&["erroronly", "successonly"])))]
pub struct EndpointInfo {
    #[clap(help = "BMC IP address of Endpoint.")]
    pub address: Option<String>,

    #[clap(
        short,
        long,
        help = "Filter based on vendor. Valid only for table view."
    )]
    pub vendor: Option<String>,

    #[clap(
        long,
        action,
        help = "By default shows all endpoints. If wants to see unpairedonly, choose this option."
    )]
    pub unpairedonly: bool,

    #[clap(long, action, help = "Show only endpoints which have error.")]
    pub erroronly: bool,

    #[clap(long, action, help = "Show only endpoints which have no error.")]
    pub successonly: bool,
}

#[derive(Parser, Debug, PartialEq)]
pub struct ManagedHostInfo {
    #[clap(help = "BMC IP address of host or DPU")]
    pub address: Option<String>,

    #[clap(
        short,
        long,
        help = "Filter based on vendor. Valid only for table view."
    )]
    pub vendor: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ExploreOptions {
    #[clap(help = "BMC IP address or hostname with optional port")]
    pub address: String,
    #[clap(long, help = "The MAC address the BMC sent DHCP from")]
    pub mac: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct CopyBfbToDpuRshimArgs {
    #[clap(help = "BMC IP address or hostname with optional port")]
    pub address: String,
    #[clap(long, help = "The MAC address the BMC sent DHCP from")]
    pub mac: Option<MacAddress>,
    #[clap(
        long,
        help = "Host BMC IP address. Provide this if you want to power cycle the host before SCPing."
    )]
    pub host_bmc_ip: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ReExploreOptions {
    #[clap(help = "BMC IP address")]
    pub address: String,
}

#[derive(Parser, Debug)]
pub struct DeleteExploredEndpointOptions {
    #[clap(long, help = "BMC IP address of the endpoint to delete")]
    pub address: String,
}

#[derive(Parser, Debug)]
pub struct RemediationOptions {
    #[clap(help = "BMC IP address of the endpoint")]
    pub address: String,
    #[clap(long, help = "Pause remediation actions", conflicts_with = "resume")]
    pub pause: bool,
    #[clap(long, help = "Resume remediation actions", conflicts_with = "pause")]
    pub resume: bool,
}
