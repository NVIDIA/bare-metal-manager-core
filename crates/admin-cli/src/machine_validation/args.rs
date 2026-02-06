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
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "External config", subcommand, visible_alias = "mve")]
    ExternalConfig(ExternalConfigCommand),
    #[clap(about = "Ondemand Validation", subcommand, visible_alias = "mvo")]
    OnDemand(OnDemandCommand),
    #[clap(
        about = "Display machine validation results of individual runs",
        subcommand,
        visible_alias = "mvr"
    )]
    Results(ResultsCommand),
    #[clap(
        about = "Display all machine validation runs",
        subcommand,
        visible_alias = "mvt"
    )]
    Runs(RunsCommand),
    #[clap(about = "Supported Tests ", subcommand, visible_alias = "mvs")]
    Tests(Box<TestsCommand>),
}

#[derive(Parser, Debug)]
pub enum ExternalConfigCommand {
    #[clap(about = "Show External config")]
    Show(ExternalConfigShowOptions),

    #[clap(about = "Update External config")]
    AddUpdate(ExternalConfigAddOptions),

    #[clap(about = "Remove External config")]
    Remove(ExternalConfigRemoveOptions),
}

#[derive(Parser, Debug)]
pub struct ExternalConfigShowOptions {
    #[clap(short, long, help = "Machine validation external config names")]
    pub name: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ExternalConfigAddOptions {
    #[clap(short, long, help = "Name of the file to update")]
    pub file_name: String,
    #[clap(short, long, help = "Name of the config")]
    pub name: String,
    #[clap(short, long, help = "description of the file to update")]
    pub description: String,
}

#[derive(Parser, Debug)]
pub struct ExternalConfigRemoveOptions {
    #[clap(short, long, help = "Machine validation external config name")]
    pub name: String,
}

#[derive(Parser, Debug)]
pub enum RunsCommand {
    #[clap(about = "Show Runs")]
    Show(ShowRunsOptions),
}

#[derive(Parser, Debug)]
pub struct ShowRunsOptions {
    #[clap(short = 'm', long, help = "Show machine validation runs of a machine")]
    pub machine: Option<MachineId>,

    #[clap(long, default_value = "false", help = "run history")]
    pub history: bool,
}

#[derive(Parser, Debug)]
pub enum ResultsCommand {
    #[clap(about = "Show results")]
    Show(ShowResultsOptions),
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
    "validation_id",
    "test_name",
    "machine",
    ])))]
pub struct ShowResultsOptions {
    #[clap(
        short = 'm',
        long,
        group = "group",
        help = "Show machine validation result of a machine"
    )]
    pub machine: Option<MachineId>,

    #[clap(short = 'v', long, group = "group", help = "Machine validation id")]
    pub validation_id: Option<String>,

    #[clap(
        short = 't',
        long,
        group = "group",
        requires("validation_id"),
        help = "Name of the test case"
    )]
    pub test_name: Option<String>,

    #[clap(long, default_value = "false", help = "Results history")]
    pub history: bool,
}

#[derive(Parser, Debug)]
pub enum OnDemandCommand {
    #[clap(about = "Start on demand machine validation")]
    Start(OnDemandOptions),
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct OnDemandOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(short, long, help = "Machine id for start validation")]
    pub machine: MachineId,

    #[clap(long, help = "Results history")]
    pub tags: Option<Vec<String>>,

    #[clap(long, help = "Allowed tests")]
    pub allowed_tests: Option<Vec<String>>,

    #[clap(long, default_value = "false", help = "Run not verfified tests")]
    pub run_unverfied_tests: bool,

    #[clap(long, help = "Contexts")]
    pub contexts: Option<Vec<String>>,
}

#[derive(Parser, Debug)]
pub enum TestsCommand {
    #[clap(about = "Show tests")]
    Show(ShowTestOptions),
    #[clap(about = "Verify a given test")]
    Verify(VerifyTestOptions),
    #[clap(about = "Add new test case")]
    Add(AddTestOptions),
    #[clap(about = "Update existing test case")]
    Update(UpdateTestOptions),
    #[clap(about = "Enabled a test")]
    Enable(EnableDisableTestOptions),
    #[clap(about = "Disable a test")]
    Disable(EnableDisableTestOptions),
}

#[derive(Parser, Debug)]
pub struct ShowTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: Option<String>,

    #[clap(short, long, help = "List of platforms")]
    pub platforms: Vec<String>,

    #[clap(short, long, help = "List of contexts/tags")]
    pub contexts: Vec<String>,

    #[clap(long, default_value = "false", help = "List unverfied tests also.")]
    pub show_un_verfied: bool,
}

#[derive(Parser, Debug)]
pub struct VerifyTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}

#[derive(Parser, Debug)]
pub struct EnableDisableTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}

#[derive(Parser, Debug)]
pub struct UpdateTestOptions {
    #[clap(long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(long, help = "Version to be verify")]
    pub version: String,

    #[clap(long, help = "List of contexts")]
    pub contexts: Vec<String>,

    #[clap(long, help = "Container image name")]
    pub img_name: Option<String>,

    #[clap(long, help = "Run command using chroot in case of container")]
    pub execute_in_host: Option<bool>,

    #[clap(long, help = "Container args", allow_hyphen_values = true)]
    pub container_arg: Option<String>,

    #[clap(long, help = "Description")]
    pub description: Option<String>,

    #[clap(long, help = "Command ")]
    pub command: Option<String>,

    #[clap(long, help = "Command args", allow_hyphen_values = true)]
    pub args: Option<String>,

    #[clap(long, help = "Command output error file ")]
    pub extra_err_file: Option<String>,

    #[clap(long, help = "Command output file ")]
    pub extra_output_file: Option<String>,

    #[clap(long, help = "External file")]
    pub external_config_file: Option<String>,

    #[clap(long, help = "Pre condition")]
    pub pre_condition: Option<String>,

    #[clap(long, help = "Command Timeout")]
    pub timeout: Option<i64>,

    #[clap(long, help = "List of supported platforms")]
    pub supported_platforms: Vec<String>,

    #[clap(long, help = "List of custom tags")]
    pub custom_tags: Vec<String>,

    #[clap(long, help = "List of system components")]
    pub components: Vec<String>,

    #[clap(long, help = "Enable the test")]
    pub is_enabled: Option<bool>,
}

#[derive(Parser, Debug)]
pub struct AddTestOptions {
    #[clap(long, help = "Name of the test case")]
    pub name: String,

    #[clap(long, help = "Command of the test case")]
    pub command: String,

    #[clap(long, help = "Command args", allow_hyphen_values = true)]
    pub args: String,

    #[clap(long, help = "List of contexts")]
    pub contexts: Vec<String>,

    #[clap(long, help = "Container image name")]
    pub img_name: Option<String>,

    #[clap(long, help = "Run command using chroot in case of container")]
    pub execute_in_host: Option<bool>,

    #[clap(long, help = "Container args", allow_hyphen_values = true)]
    pub container_arg: Option<String>,

    #[clap(long, help = "Description")]
    pub description: Option<String>,

    #[clap(long, help = "Command output error file ")]
    pub extra_err_file: Option<String>,

    #[clap(long, help = "Command output file ")]
    pub extra_output_file: Option<String>,

    #[clap(long, help = "External file")]
    pub external_config_file: Option<String>,

    #[clap(long, help = "Pre condition")]
    pub pre_condition: Option<String>,

    #[clap(long, help = "Command Timeout")]
    pub timeout: Option<i64>,

    #[clap(long, help = "List of supported platforms")]
    pub supported_platforms: Vec<String>,

    #[clap(long, help = "List of custom tags")]
    pub custom_tags: Vec<String>,

    #[clap(long, help = "List of system components")]
    pub components: Vec<String>,

    #[clap(long, help = "Enable the test")]
    pub is_enabled: Option<bool>,

    #[clap(long, help = "Is read-only")]
    pub read_only: Option<bool>,
}
