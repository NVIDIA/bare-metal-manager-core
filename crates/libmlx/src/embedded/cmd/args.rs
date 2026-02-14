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

use crate::device::cmd::device::args::DeviceAction;
use crate::lockdown::cmd::args::LockdownAction;

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

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Parser)]
#[command(name = "mlxconfig-embedded")]
#[command(about = "CLI reference example for Forge mlxconfig management crates")]
#[command(version = "0.0.1")]
pub struct Cli {
    // --log-level controls the tracing output level (default: info).
    // Can be overridden by the RUST_LOG environment variable.
    #[arg(long, default_value = "info")]
    pub log_level: LogLevel,

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

    // Firmware is for firmware flash, verify, and reset operations,
    // using the mlxconfig-firmware crate.
    Firmware {
        // --dry-run enables dry-run mode.
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        // --work-dir is the staging directory for downloaded files.
        #[arg(long)]
        work_dir: Option<PathBuf>,

        // firmware_action contains the firmware subcommand to execute.
        #[command(subcommand)]
        firmware_action: FirmwareAction,
    },
}

// FirmwareAction contains all available subcommands
// under the `firmware` command.
#[derive(Subcommand)]
pub enum FirmwareAction {
    // flash runs the full firmware flash lifecycle: optionally
    // apply device config, then burn firmware via flint.
    Flash {
        // device is the PCI address of the target device (e.g., "01:00.0").
        device: String,

        // firmware_url is the firmware source. Supports:
        //   local path:  /path/to/firmware.signed.bin
        //   file:// URL: file:///path/to/firmware.signed.bin
        //   HTTPS URL:   https://host/path/to/firmware.bin
        //   SSH URL:     ssh://user@host:path/to/firmware.bin
        firmware_url: String,

        // --device-conf-url is the optional device config source
        // (e.g., debug token). Same URL formats as firmware_url.
        #[arg(long)]
        device_conf_url: Option<String>,

        // --firmware-bearer-token sets a bearer token for HTTPS
        // firmware downloads.
        #[arg(long)]
        firmware_bearer_token: Option<String>,

        // --firmware-basic-auth sets basic auth (user:pass) for
        // HTTPS firmware downloads.
        #[arg(long)]
        firmware_basic_auth: Option<String>,

        // --firmware-ssh-key sets the SSH private key path for
        // SSH firmware downloads.
        #[arg(long)]
        firmware_ssh_key: Option<PathBuf>,

        // --firmware-ssh-agent uses the SSH agent for SSH firmware
        // downloads.
        #[arg(long)]
        firmware_ssh_agent: bool,

        // --device-conf-bearer-token sets a bearer token for HTTPS
        // device config downloads.
        #[arg(long)]
        device_conf_bearer_token: Option<String>,

        // --device-conf-basic-auth sets basic auth (user:pass) for
        // HTTPS device config downloads.
        #[arg(long)]
        device_conf_basic_auth: Option<String>,

        // --device-conf-ssh-key sets the SSH private key path for
        // SSH device config downloads.
        #[arg(long)]
        device_conf_ssh_key: Option<PathBuf>,

        // --device-conf-ssh-agent uses the SSH agent for SSH device
        // config downloads.
        #[arg(long)]
        device_conf_ssh_agent: bool,

        // --expected-version is the firmware version to verify after
        // flashing (e.g., "32.43.1014").
        #[arg(long)]
        expected_version: Option<String>,
    },

    // flash-config loads firmware configuration from a TOML file
    // and executes the flash lifecycle.
    #[command(name = "flash-config")]
    FlashConfig {
        // device is the PCI address of the target device.
        device: String,

        // config_file is the path to the TOML configuration file.
        config_file: PathBuf,
    },

    // verify-image verifies device firmware by comparing against
    // a provided firmware image. Supports remote sources (HTTPS,
    // SSH) — the image is downloaded first, then verified via flint.
    #[command(name = "verify-image")]
    VerifyImage {
        // device is the PCI address of the target device.
        device: String,

        // image_url is the firmware image to verify against.
        // Supports local paths, file://, https://, and ssh:// URLs.
        image_url: String,

        // --bearer-token sets a bearer token for HTTPS downloads.
        #[arg(long)]
        bearer_token: Option<String>,

        // --basic-auth sets basic auth (user:pass) for HTTPS downloads.
        #[arg(long)]
        basic_auth: Option<String>,

        // --ssh-key sets the SSH private key path for SSH downloads.
        #[arg(long)]
        ssh_key: Option<PathBuf>,

        // --ssh-agent uses the SSH agent for SSH downloads.
        #[arg(long)]
        ssh_agent: bool,
    },

    // verify-version checks that the installed firmware version
    // matches the expected version.
    #[command(name = "verify-version")]
    VerifyVersion {
        // device is the PCI address of the target device.
        device: String,

        // expected_version is the version string to compare against.
        expected_version: String,
    },

    // reset runs mlxfwreset on the device to activate new firmware.
    Reset {
        // device is the PCI address of the target device.
        device: String,

        // --level is the mlxfwreset level (default 3).
        #[arg(short, long, default_value = "3")]
        level: u8,
    },

    // config-reset resets all mlxconfig NV configuration parameters
    // on the device to their factory default values. This is NOT a
    // device reset — use `reset` for that.
    #[command(name = "config-reset")]
    ConfigReset {
        // device is the PCI address of the target device.
        device: String,
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
