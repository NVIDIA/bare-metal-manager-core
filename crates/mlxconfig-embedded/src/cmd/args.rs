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

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mlxconfig_device::cmd::device::args::DeviceAction;
use mlxconfig_lockdown::cmd::args::LockdownAction;

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    #[value(name = "table")]
    AsciiTable,
    #[value(name = "json")]
    Json,
    #[value(name = "yaml")]
    Yaml,
}

#[derive(Parser)]
#[command(name = "mlxconfig-embedded")]
#[command(about = "CLI reference example for Forge mlxconfig management crates")]
#[command(version = "0.0.1")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    // Version shows `version` information.
    Version,
    // Registry is for `registry` management commands, allowing you
    // to look at the current registries and their variables via
    // the mlxconfig-registry interface.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
    // Runner is for `runner` subcommands, allowing you to interact
    // with the mlxconfig-runner features.
    #[command(name = "runner")]
    Runner {
        // --device is the device identifier (PCI address),
        // and defaults to 01:00.0.
        #[arg(short, long, default_value = "01:00.0")]
        device: String,

        // --verbose enables verbose output.
        #[arg(short, long)]
        verbose: bool,

        // --dry-run enables dry-run mode, where any destructive
        // commands (set and sync) don't actually get executed.
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        // --retries is the number of retries to perform if
        // the mlxconfig command run returns an error.
        #[arg(short = 'r', long, default_value = "0")]
        retries: u32,

        // --timeout gives us the ability to set a timeout on
        // the actual run of mlxconfig, if it happens to be
        // hanging for some reason.
        #[arg(short = 't', long, default_value = "30")]
        timeout: u64,

        // --confirm provides an option to require confirmation
        // before applying changes to certain variables.
        #[arg(short = 'c', long)]
        confirm: bool,

        // runner_command contains the runner subcommand to execute.
        #[command(subcommand)]
        runner_command: RunnerCommands,
    },
    // Profile is for profile-based configuration management,
    // allowing you to sync and compare YAML-defined profiles.
    Profile {
        // --device is the device identifier (PCI address),
        // and defaults to 01:00.0.
        #[arg(short, long, default_value = "01:00.0")]
        device: String,

        // --verbose enables verbose output.
        #[arg(short, long)]
        verbose: bool,

        // --dry-run enables dry-run mode, where any destructive
        // commands don't actually get executed.
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        // --retries is the number of retries to perform if
        // the mlxconfig command run returns an error.
        #[arg(short = 'r', long, default_value = "0")]
        retries: u32,

        // --timeout gives us the ability to set a timeout on
        // the actual run of mlxconfig.
        #[arg(short = 't', long, default_value = "30")]
        timeout: u64,

        // --confirm provides an option to require confirmation
        // before applying changes to certain variables.
        #[arg(short = 'c', long)]
        confirm: bool,

        // profile_command contains the profile subcommand to execute.
        #[command(subcommand)]
        profile_command: ProfileCommands,
    },
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    Lockdown {
        #[command(subcommand)]
        action: LockdownAction,
    },
}

#[derive(Subcommand)]
pub enum RegistryAction {
    // `registry generate` is used to generate a registry YAML
    // file from `mlxconfig show_confs` output. Note that `show_confs`
    // does NOT annotate which variables are array types, so the
    // YAML it generates is not 100% accurate. For accuracy, we'll
    // need to update this to *also* query the device to see which
    // variables *ARE* arrays, and then generate accordingly.
    // TODO(chet): If we end up wanting this, I can do it.
    Generate {
        // input_file is the input file containing show_confs output.
        input_file: PathBuf,
        // output_file is the optional path to dump the generated
        // registry YAML config to (default: stdout).
        #[arg(short, long)]
        out_file: Option<PathBuf>,
    },
    // `registry validate` is used to validate an existing
    // registry YAML file, useful if you're making your own,
    // or want to make sure the generated one is correct.
    Validate {
        // yaml_file is the path to the registry YAML file
        // to validate.
        yaml_file: PathBuf,
    },
    // `registry list` is used to list all available
    // registry names.
    List,
    // `registry show` shows details about a specific registry,
    // including any constraints and it's registered variables.
    Show {
        // registry_name is the name of the registry to show
        // details for.
        registry_name: String,
        // output is the output format to use. Table gives you
        // a prettytable, JSON also works, and YAML dumps back
        // the registry YAML.
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    // `registry check` is used to check if the input device
    // info is compatible with the given registry.
    Check {
        // registry_name is the name of the registry to be
        // checking against.
        registry_name: String,
        // device_type is an optional device type (e.g.
        // "Bluefield3", "ConnectX-7") to check compatibility
        // against.
        #[arg(long)]
        device_type: Option<String>,
        // part_number is an optional art number (e.g.,
        // "900-9D3D4-00EN-HA0") to check compatibility
        // against.
        #[arg(long)]
        part_number: Option<String>,
        // fw_version is an optional firmware version
        // (e.g., "32.41.130") to check compatibility
        // against.
        #[arg(long)]
        fw_version: Option<String>,
    },
}

// RunnerCommands contains all available subcommands
// under the `runner` command.
#[derive(Subcommand)]
pub enum RunnerCommands {
    // query will query variables for a given registry,
    // or all variables from the registry if no specific
    // variables are provided.
    Query {
        // registry is the registry to query.
        registry: String,

        // variables is an optional list of variables to query from
        // the given registry. If unset, all variables configured in
        // the registry will be queried.
        #[arg(short, long, value_delimiter = ',')]
        variables: Option<Vec<String>>,

        // format is the output format for results. By default it
        // prints a pretty ASCII table, but you can also do JSON
        // or YAML (see OutputFormat for options).
        #[arg(short = 'f', long, default_value = "table")]
        format: OutputFormat,
    },

    // set is used to set variable values.
    Set {
        // registry is the registry to use, which will be used
        // to look up the variable definitions for the variables
        // being set.
        registry: String,

        // assignments is the comma-separated list of key=val
        // variable assignments to make. For array indices, you
        // set them as VAR_NAME[index]=val (e.g. VAR_NAME[0]=cat),
        // and we will behind the scenes do the necessary work
        // to make it happen.
        #[arg(required = true, value_delimiter = ',')]
        assignments: Vec<String>,
    },

    // sync synchronizes the key=val variable assignments provided,
    // by first doing a query of the variables to get their current
    // value(s), and then only doing a `set` for the variables which
    // need to be changed.
    Sync {
        // registry to use for getting variable definitions.
        registry: String,

        // assignments is the comma-separated list of key=val
        // variable assignments to make. For array indices, you
        // set them as VAR_NAME[index]=val (e.g. VAR_NAME[0]=cat),
        // and we will behind the scenes do the necessary work
        // to make it happen.
        #[arg(required = true, value_delimiter = ',')]
        assignments: Vec<String>,
    },

    // compare will compare desired key=val variable assignments
    // against what is currently configured on the device. This
    // is effectively like doing a dry-run version of a sync.
    Compare {
        // registry to use for getting variable definitions.
        registry: String,

        // assignments is the comma-separated list of key=val
        // variable assignments to check against the device.
        // For array indices, you set them as VAR_NAME[index]=val
        // (e.g. VAR_NAME[0]=cat), and we will behind the scenes
        // do the necessary work to make it happen.
        #[arg(required = true, value_delimiter = ',')]
        assignments: Vec<String>,
    },
}

// ProfileCommands contains all available subcommands
// under the `profile` command.
#[derive(Subcommand)]
pub enum ProfileCommands {
    // sync synchronizes a YAML profile to the specified device.
    Sync {
        // yaml_path is the path to the YAML profile file.
        yaml_path: PathBuf,
    },
    // compare compares a YAML profile against the current device state.
    Compare {
        // yaml_path is the path to the YAML profile file.
        yaml_path: PathBuf,
    },
}
