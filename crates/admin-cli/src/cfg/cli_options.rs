/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::{Parser, ValueEnum, ValueHint};
use rpc::admin_cli::OutputFormat;
use rpc::forge::RouteServerSourceType;

use crate::cfg::measurement;
use crate::{
    bmc_machine, boot_override, credential, devenv, domain, dpa, dpu, dpu_remediation,
    expected_machines, expected_power_shelf, expected_switch, extension_service, firmware,
    generate_shell_complete, host, ib_partition, instance, instance_type, inventory, ip, jump,
    machine, machine_interfaces, machine_validation, managed_host, mlx, network_devices,
    network_security_group, network_segment, nvl_logical_partition, nvl_partition, os_image, ping,
    power_shelf, rack, redfish, resource_pool, rms, scout_stream, set, site_explorer, sku, ssh,
    switch, tenant, tenant_keyset, tpm_ca, trim_table, version, vpc, vpc_peering, vpc_prefix,
};

#[derive(Parser, Debug)]
#[clap(name = "forge-admin-cli")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct CliOptions {
    #[clap(
        long,
        default_value = "false",
        help = "Print version number of forge-admin-cli and exit. For API server version see 'version' command."
    )]
    pub version: bool,

    #[clap(
        long,
        value_hint = ValueHint::Username,
        value_name = "USERNAME",
        help = "Never should be used against a production site. Use this flag only if you understand the impacts of inconsistencies with cloud db."
    )]
    pub cloud_unsafe_op: Option<String>,

    #[clap(short, long, env = "CARBIDE_API_URL")]
    #[clap(
        help = "Default to CARBIDE_API_URL environment variable or $HOME/.config/carbide_api_cli.json file or https://carbide-api.forge-system.svc.cluster.local:1079."
    )]
    pub carbide_api: Option<String>,

    #[clap(short, long, value_enum, default_value = "ascii-table")]
    pub format: OutputFormat,

    #[clap(short, long)]
    pub output: Option<String>,

    #[clap(long, env = "FORGE_ROOT_CA_PATH")]
    #[clap(
        help = "Default to FORGE_ROOT_CA_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub forge_root_ca_path: Option<String>,

    #[clap(long, env = "CLIENT_CERT_PATH")]
    #[clap(
        help = "Default to CLIENT_CERT_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub client_cert_path: Option<String>,

    #[clap(long, env = "CLIENT_KEY_PATH")]
    #[clap(
        help = "Default to CLIENT_KEY_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub client_key_path: Option<String>,

    #[clap(short, long, num_args(0..), default_value = "0")]
    pub debug: u8,

    // This is primarily used by measured boot, where basic output contains just
    // what you probably care about, and "extended" output also dumps out all of
    // the internal UUIDs that are used to associate instances. Helpful for filing
    // reports, doing site import/exports, etc.
    #[clap(long, global = true, help = "Extended result output.")]
    pub extended: bool,

    #[clap(subcommand)]
    pub commands: Option<CliCommand>,

    #[clap(short = 'p', long, default_value_t = 100)]
    #[clap(help = "For commands that internally retrieve data with paging, use this page size.")]
    pub internal_page_size: usize,

    #[clap(
        long,
        value_enum,
        global = true,
        help = "Sort output by specified field",
        default_value = "primary-id"
    )]
    pub sort_by: SortField,
}

#[derive(PartialEq, Eq, ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum SortField {
    #[clap(help = "Sort by the primary id")]
    PrimaryId,
    #[clap(help = "Sort by state")]
    State,
}

#[derive(Parser, Debug)]
pub enum CliCommand {
    #[clap(about = "Print API server version", visible_alias = "v")]
    Version(version::Opts),
    #[clap(about = "Machine related handling", subcommand, visible_alias = "m")]
    Machine(machine::Cmd),
    #[clap(about = "Instance related handling", subcommand, visible_alias = "i")]
    Instance(instance::Cmd),
    #[clap(
        about = "Network Segment related handling",
        subcommand,
        visible_alias = "ns"
    )]
    NetworkSegment(network_segment::Cmd),
    #[clap(about = "Domain related handling", subcommand, visible_alias = "d")]
    Domain(domain::Cmd),
    #[clap(
        about = "Managed host related handling",
        subcommand,
        visible_alias = "mh"
    )]
    ManagedHost(managed_host::Cmd),
    #[clap(
        subcommand,
        about = "Work with measured boot data.",
        visible_alias = "mb"
    )]
    Measurement(measurement::Cmd),
    #[clap(about = "Resource pool handling", subcommand, visible_alias = "rp")]
    ResourcePool(resource_pool::Cmd),
    #[clap(about = "Redfish BMC actions", visible_alias = "rf")]
    Redfish(redfish::RedfishAction),
    #[clap(about = "Network Devices handling", subcommand)]
    NetworkDevice(network_devices::Cmd),
    #[clap(about = "IP address handling", subcommand)]
    Ip(ip::Cmd),
    #[clap(about = "DPU specific handling", subcommand)]
    Dpu(dpu::Cmd),
    #[clap(about = "Host specific handling", subcommand)]
    Host(host::Cmd),
    #[clap(about = "Generate Ansible Inventory")]
    Inventory(inventory::Cmd),
    #[clap(about = "Machine boot override", subcommand)]
    BootOverride(boot_override::Cmd),
    #[clap(
        about = "BMC Machine related handling",
        subcommand,
        visible_alias = "bmc"
    )]
    BmcMachine(bmc_machine::Cmd),
    #[clap(about = "Credential related handling", subcommand, visible_alias = "c")]
    Credential(credential::Cmd),
    #[clap(about = "Route server handling", subcommand)]
    RouteServer(RouteServer),
    #[clap(about = "Site explorer functions", subcommand)]
    SiteExplorer(site_explorer::Cmd),
    #[clap(
        about = "List of all Machine interfaces",
        subcommand,
        visible_alias = "mi"
    )]
    MachineInterfaces(machine_interfaces::Cmd),
    #[clap(
        about = "Generate shell autocomplete. Source the output of this command: `source <(forge-admin-cli generate-shell-complete bash)`"
    )]
    GenerateShellComplete(generate_shell_complete::Cmd),
    #[clap(
        about = "Query the Version gRPC endpoint repeatedly printing how long it took and any failures."
    )]
    Ping(ping::Opts),
    #[clap(about = "Set carbide-api dynamic features", subcommand)]
    Set(set::Cmd),
    #[clap(about = "Expected machine handling", subcommand, visible_alias = "em")]
    ExpectedMachine(expected_machines::Cmd),
    #[clap(
        about = "Expected power shelf handling",
        subcommand,
        visible_alias = "ep"
    )]
    ExpectedPowerShelf(expected_power_shelf::Cmd),
    #[clap(about = "Expected switch handling", subcommand, visible_alias = "ew")]
    ExpectedSwitch(expected_switch::Cmd),
    #[clap(about = "VPC related handling", subcommand)]
    Vpc(vpc::Cmd),
    #[clap(about = "VPC peering handling", subcommand)]
    VpcPeering(vpc_peering::Cmd),
    #[clap(about = "VPC prefix handling", subcommand)]
    VpcPrefix(vpc_prefix::Cmd),
    #[clap(
        about = "InfiniBand Partition related handling",
        subcommand,
        visible_alias = "ibp"
    )]
    IbPartition(ib_partition::Cmd),
    #[clap(
        about = "Tenant KeySet related handling",
        subcommand,
        visible_alias = "tks"
    )]
    TenantKeySet(tenant_keyset::Cmd),

    #[clap(
        about = "Broad search across multiple object types",
        visible_alias = "j"
    )]
    Jump(jump::Cmd),

    #[clap(about = "Machine Validation", subcommand, visible_alias = "mv")]
    MachineValidation(machine_validation::Cmd),

    #[clap(about = "OS catalog management", visible_alias = "os", subcommand)]
    OsImage(os_image::Cmd),

    #[clap(about = "Manage TPM CA certificates", subcommand)]
    TpmCa(tpm_ca::Cmd),

    #[clap(
        about = "Network security group management",
        visible_alias = "nsg",
        subcommand
    )]
    NetworkSecurityGroup(network_security_group::Cmd),

    #[clap(about = "Manage machine SKUs", subcommand)]
    Sku(sku::Cmd),

    #[clap(about = "Dev Env related handling", subcommand)]
    DevEnv(devenv::Cmd),

    #[clap(about = "Instance type management", visible_alias = "it", subcommand)]
    InstanceType(instance_type::Cmd),

    #[clap(about = "SSH Util functions", subcommand)]
    Ssh(ssh::Cmd),

    #[clap(about = "Power Shelf management", subcommand, visible_alias = "ps")]
    PowerShelf(power_shelf::Cmd),

    #[clap(about = "Switch management", subcommand, visible_alias = "sw")]
    Switch(switch::Cmd),

    #[clap(about = "Rack Management", subcommand)]
    Rack(rack::Cmd),

    #[clap(about = "Rms Actions", subcommand)]
    Rms(rms::Cmd),

    #[clap(about = "Firmware related actions", subcommand)]
    Firmware(firmware::Cmd),

    #[clap(about = "DPA related handling", subcommand)]
    Dpa(dpa::Cmd),
    #[clap(about = "Trim DB tables", subcommand)]
    TrimTable(trim_table::Cmd),
    #[clap(about = "Dpu Remediation handling", subcommand)]
    DpuRemediation(dpu_remediation::Cmd),
    #[clap(
        about = "Extension service management",
        visible_alias = "es",
        subcommand
    )]
    ExtensionService(extension_service::Cmd),
    #[clap(about = "Mellanox Device Handling", subcommand)]
    Mlx(mlx::MlxAction),
    #[clap(about = "Scout Stream Connection Handling", subcommand)]
    ScoutStream(scout_stream::ScoutStreamAction),
    #[clap(
        about = "NvLink Partition related handling",
        subcommand,
        visible_alias = "nvp"
    )]
    NvlPartition(nvl_partition::Cmd),

    #[clap(
        about = "Logical partition related handling",
        subcommand,
        visible_alias = "lp"
    )]
    LogicalPartition(nvl_logical_partition::Cmd),

    #[clap(about = "Tenant management", subcommand, visible_alias = "tm")]
    Tenant(tenant::Cmd),
}

impl CliOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[derive(Parser, Debug)]
pub enum RouteServer {
    Get,
    Add(RouteServerAddresses),
    Remove(RouteServerAddresses),
    Replace(RouteServerAddresses),
}

// RouteServerAddresses is used for add/remove/replace
// operations for route server addresses, with support
// for overriding the source_type to not be admin_api,
// and make ephemeral changes against whatever was
// loaded up via the config file at start.
#[derive(Parser, Debug)]
pub struct RouteServerAddresses {
    #[arg(value_delimiter = ',', help = "Comma-separated list of IPv4 addresses")]
    pub ip: Vec<std::net::Ipv4Addr>,
    // The optional source_type to set. If unset, this
    // defaults to admin_api, which is what we'd expect.
    // Override with --source_type=config to make
    // ephemeral changes to config file-based entries,
    // which is really intended for break-glass types
    // of scenarios.
    #[arg(
        long,
        default_value = "admin_api",
        help = "The source_type to use for the target addresses. Defaults to admin_api."
    )]
    pub source_type: RouteServerSourceType,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::expected_machines::Cmd::Patch;
    use crate::expected_machines::args::{ExpectedMachine, PatchExpectedMachine};

    #[test]
    fn forge_admin_cli_expected_machine_test() {
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
            ])
            .is_ok()
        );

        // No dpu serial
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
            ])
            .is_ok_and(|t1| { !t1.has_duplicate_dpu_serials() })
        );

        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number",
                "dpu_serial",
            ])
            .is_ok()
        );

        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number",
                "dpu_serial",
                "-d",
                "dpu_serial2",
            ])
            .is_ok()
        );

        // Duplicate dpu_serial
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "-d",
                "dpu_serial1",
                "-d",
                "dpu_serial2",
                "-d",
                "dpu_serial3",
                "-d",
                "dpu_serial1"
            ])
            .is_ok_and(|t| { t.has_duplicate_dpu_serials() })
        );

        // option --fallback-dpu-serial-number used w/o value
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number"
            ])
            .is_err()
        );

        fn test_patch_expected_machine<F: Fn(PatchExpectedMachine) -> bool>(
            options: CliOptions,
            pred: F,
        ) -> bool {
            let mut patch_args = None;
            if let Some(CliCommand::ExpectedMachine(Patch(args))) = options.commands {
                patch_args = Some(args);
            }
            patch_args.is_some() && pred(patch_args.unwrap())
        }
        // Test patch command: 1 dpu serial
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // Test patch command: 2 dpu serials
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER_1>",
                "-d",
                "<DPU_SERIAL_NUMBER_2>",
            ])
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
            ])
            .is_err()
        );

        // Fail if duplicate dpu serials are given
        // duplicate dpu serials -
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "dpu1",
                "-d",
                "dpu2",
                "-d",
                "dpu3",
                "-d",
                "dpu2",
                "-d",
                "dpu4",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_err() }
        ));

        // Test patch command: update credential
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "<BMC_USERNAME>",
                "--bmc-password",
                "<BMC_PASSWORD>",
            ])
            .is_ok()
        );
        // Test patch command: update all fields
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
                "--bmc-password",
                "ssss",
                "--chassis-serial-number",
                "sss",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // Test patch command: username only - should error (requires password)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
            ])
            .is_err()
        );
        // Test patch command: password only - should error (requires username)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-password",
                "ssss",
            ])
            .is_err()
        );

        // Test update command (full replacement from JSON file)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--filename",
                "/path/to/machine.json",
            ])
            .is_ok()
        );

        // Test update command with short flag
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "-f",
                "/path/to/machine.json",
            ])
            .is_ok()
        );

        // Test update command without filename - should fail
        assert!(
            CliOptions::try_parse_from(["forge-admin-cli", "expected-machine", "update",]).is_err()
        );

        // Test update command with CLI args (not JSON) - should fail
        // update only accepts --filename, not individual fields
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--sku-id",
                "sku123",
            ])
            .is_err()
        );
    }

    #[test]
    fn forge_admin_cli_credential_test() {
        //  bmc-root credential w.o optional username
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "credential",
                "add-bmc",
                "--kind=bmc-root",
                "--mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--password",
                "my-pw",
            ])
            .is_ok()
        );

        //  bmc-root credential with optional username
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "credential",
                "add-bmc",
                "--kind=bmc-root",
                "--mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--password",
                "my-pw",
                "--username",
                "me"
            ])
            .is_ok()
        );
    }

    #[test]
    fn forge_admin_cli_tpm_ca_test() {
        assert!(CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "show"]).is_ok());

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add",
                "--filename",
                "/tmp/somefile.cer"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add-bulk",
                "--dirname",
                "/tmp"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "delete", "--ca-id", "4"])
                .is_ok()
        );
    }
}
