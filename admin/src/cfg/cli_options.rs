use clap::builder::BoolishValueParser;
use std::collections::HashMap;
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
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum, ValueHint};
use ipnet::IpNet;
use mac_address::MacAddress;

use forge_network::virtualization::VpcVirtualizationType;
use forge_ssh::ssh::{
    DEFAULT_SSH_SESSION_TIMEOUT, DEFAULT_TCP_CONNECTION_TIMEOUT, DEFAULT_TCP_READ_TIMEOUT,
    DEFAULT_TCP_WRITE_TIMEOUT, SshConfig,
};
use forge_uuid::machine::MachineId;
use forge_uuid::vpc::{VpcId, VpcPrefixId};
use libredfish::model::update_service::ComponentType;
use rpc::forge::{OperatingSystem, SshTimeoutConfig};
use serde::{Deserialize, Serialize};
use utils::{admin_cli::OutputFormat, has_duplicates};

use crate::cfg::instance_type;
use crate::cfg::measurement;
use crate::cfg::network_security_group;
use crate::cfg::storage::{OsImageActions, StorageActions};
use crate::vpc_prefix::VpcPrefixSelector;

const DEFAULT_IB_FABRIC_NAME: &str = "default";

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
        help = "Never should be used against a production site. Use this flag only if you undrestand the impacts of inconsistencies with cloud db."
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
    Version(Version),
    #[clap(about = "Machine related handling", subcommand, visible_alias = "m")]
    Machine(Machine),
    #[clap(about = "Instance related handling", subcommand, visible_alias = "i")]
    Instance(Instance),
    #[clap(
        about = "Network Segment related handling",
        subcommand,
        visible_alias = "ns"
    )]
    NetworkSegment(NetworkSegment),
    #[clap(about = "Domain related handling", subcommand, visible_alias = "d")]
    Domain(Domain),
    #[clap(
        about = "Managed host related handling",
        subcommand,
        visible_alias = "mh"
    )]
    ManagedHost(ManagedHost),
    #[clap(
        subcommand,
        about = "Work with measured boot data.",
        visible_alias = "mb"
    )]
    Measurement(measurement::Cmd),
    #[clap(about = "Resource pool handling", subcommand, visible_alias = "rp")]
    ResourcePool(ResourcePool),
    #[clap(about = "Redfish BMC actions", visible_alias = "rf")]
    Redfish(RedfishAction),
    #[clap(about = "Network Devices handling", subcommand)]
    NetworkDevice(NetworkDeviceAction),
    #[clap(about = "IP address handling", subcommand)]
    Ip(IpAction),
    #[clap(about = "DPU specific handling", subcommand)]
    Dpu(DpuAction),
    #[clap(about = "Host specific handling", subcommand)]
    Host(HostAction),
    #[clap(about = "Generate Ansible Inventory")]
    Inventory(InventoryAction),
    #[clap(about = "Machine boot override", subcommand)]
    BootOverride(BootOverrideAction),
    #[clap(
        about = "BMC Machine related handling",
        subcommand,
        visible_alias = "bmc"
    )]
    BmcMachine(BmcAction),
    #[clap(about = "Credential related handling", subcommand, visible_alias = "c")]
    Credential(CredentialAction),
    #[clap(about = "Route server handling", subcommand)]
    RouteServer(RouteServer),
    #[clap(about = "Site explorer functions", subcommand)]
    SiteExplorer(SiteExplorer),
    #[clap(
        about = "List of all Machine interfaces",
        subcommand,
        visible_alias = "mi"
    )]
    MachineInterfaces(MachineInterfaces),
    #[clap(
        about = "Generate shell autocomplete. Source the output of this command: `source <(forge-admin-cli generate-shell-complete bash)`"
    )]
    GenerateShellComplete(ShellCompleteAction),
    #[clap(
        about = "Query the Version gRPC endpoint repeatedly printing how long it took and any failures."
    )]
    Ping(PingOptions),
    #[clap(about = "Set carbide-api dynamic features", subcommand)]
    Set(SetAction),
    #[clap(about = "Expected machine handling", subcommand, visible_alias = "em")]
    ExpectedMachine(ExpectedMachineAction),
    #[clap(about = "VPC related handling", subcommand)]
    Vpc(VpcOptions),
    #[clap(about = "VPC peering handling", subcommand)]
    VpcPeering(VpcPeeringOptions),
    #[clap(about = "VPC prefix handling", subcommand)]
    VpcPrefix(VpcPrefixOptions),
    #[clap(
        about = "InfiniBand Partition related handling",
        subcommand,
        visible_alias = "ibp"
    )]
    IbPartition(IbPartitionOptions),
    #[clap(
        about = "Tenant KeySet related handling",
        subcommand,
        visible_alias = "tks"
    )]
    TenantKeySet(TenantKeySetOptions),

    #[clap(
        about = "Broad search across multiple object types",
        visible_alias = "j"
    )]
    Jump(JumpOptions),

    #[clap(about = "Machine Validation", subcommand, visible_alias = "mv")]
    MachineValidation(MachineValidationCommand),

    #[clap(
        about = "Storage management commands",
        visible_alias = "st",
        subcommand
    )]
    Storage(StorageActions),
    #[clap(about = "OS catalog management", visible_alias = "os", subcommand)]
    OsImage(OsImageActions),

    #[clap(about = "Manage TPM CA certificates", subcommand)]
    TpmCa(TpmCa),

    #[clap(
        about = "Network security group management",
        visible_alias = "nsg",
        subcommand
    )]
    NetworkSecurityGroup(network_security_group::NetworkSecurityGroupActions),

    #[clap(about = "Manage machine SKUs", subcommand)]
    Sku(Sku),

    #[clap(about = "Dev Env related handling", subcommand)]
    DevEnv(DevEnv),

    #[clap(about = "Instance type management", visible_alias = "it", subcommand)]
    InstanceType(instance_type::InstanceTypeActions),

    #[clap(about = "SSH Util functions", subcommand)]
    Ssh(SshActions),
}

#[derive(Parser, Debug)]
pub enum TpmCa {
    #[clap(about = "Show all TPM CA certificates")]
    Show,
    #[clap(about = "Delete TPM CA certificate with a given id")]
    Delete(TpmCaDbId),
    #[clap(about = "Add TPM CA certificate encoded in DER/CER/PEM format in a given file")]
    Add(TpmCaFile),
    #[clap(about = "Show TPM EK certificates for which there is no CA match")]
    ShowUnmatchedEk,
    #[clap(about = "Add all certificates in a dir as CA certificates")]
    AddBulk(TpmCaDir),
}

#[derive(Parser, Debug)]
pub struct TpmCaDir {
    #[clap(short, long, help = "Directory path containing all CA certs")]
    pub dirname: String,
}

#[derive(Parser, Debug)]
pub struct TpmCaDbId {
    #[clap(short, long, help = "TPM CA id obtained from the show command")]
    pub ca_id: i32,
}

#[derive(Parser, Debug)]
pub struct TpmCaFile {
    #[clap(short, long, help = "File name containing certificate in DER format")]
    pub filename: String,
}

#[derive(Parser, Debug)]
pub enum SetAction {
    #[clap(about = "Set RUST_LOG")]
    LogFilter(LogFilterOptions),
    #[clap(about = "Set create_machines")]
    CreateMachines(CreateMachinesOptions),
    #[clap(about = "Set bmc_proxy")]
    BmcProxy(BmcProxyOptions),
    #[clap(
        about = "Configure whether trace/span information is sent to an OTLP endpoint like Tempo"
    )]
    TracingEnabled {
        #[arg(num_args = 1, value_parser = BoolishValueParser::new(), action = clap::ArgAction::Set, value_name = "true|false")]
        value: bool,
    },
}

#[derive(Parser, Debug)]
pub struct Version {
    #[clap(short, long, action, help = "Display Runtime Config also.")]
    pub show_runtime_config: bool,
}

#[derive(Parser, Debug)]
pub struct InventoryAction {
    #[clap(short, long, help = "Write to file")]
    pub filename: Option<String>,
}

#[derive(Parser, Debug)]
pub enum DpuAction {
    #[clap(subcommand, about = "DPU Reprovisioning handling")]
    Reprovision(DpuReprovision),
    #[clap(about = "Get or set forge-dpu-agent upgrade policy")]
    AgentUpgradePolicy(AgentUpgrade),
    #[clap(about = "View DPU firmware status")]
    Versions(DpuVersionOptions),
    #[clap(about = "View DPU Status")]
    Status,
    #[clap(subcommand, about = "Networking information")]
    Network(NetworkCommand),
}

#[derive(Parser, Debug)]
pub enum DpuReprovision {
    #[clap(about = "Set the DPU in reprovisioning mode.")]
    Set(DpuReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(DpuReprovisionClear),
    #[clap(about = "List all DPUs pending reprovisioning.")]
    List,
    #[clap(about = "Restart the DPU reprovision.")]
    Restart(DpuReprovisionRestart),
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionSet {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning is needed, or host machine id if all DPUs should be reprovisioned."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,

    #[clap(
        long,
        alias = "maintenance_reference",
        help = "If set, a HostUpdateInProgress health alert will be applied to the host"
    )]
    pub update_message: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionClear {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning should be cleared, or host machine id if all DPUs should be cleared."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionRestart {
    #[clap(
        short,
        long,
        help = "Host Machine ID for which reprovisioning should be restarted."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuVersionOptions {
    #[clap(short, long, help = "Only show DPUs that need upgrades")]
    pub updates_only: bool,
}

#[derive(Parser, Debug)]
pub enum HostAction {
    #[clap(about = "Set Host UEFI password")]
    SetUefiPassword(MachineQuery),
    #[clap(about = "Clear Host UEFI password")]
    ClearUefiPassword(MachineQuery),
    #[clap(about = "Generates a string that can be a site-default host UEFI password in Vault")]
    /// - the generated string will meet the uefi password requirements of all vendors
    GenerateHostUefiPassword,
    #[clap(subcommand, about = "Host reprovisioning handling")]
    Reprovision(HostReprovision),
}

#[derive(Parser, Debug)]
pub enum HostReprovision {
    #[clap(about = "Set the host in reprovisioning mode.")]
    Set(HostReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(HostReprovisionClear),
    #[clap(about = "List all hosts pending reprovisioning.")]
    List,
}

#[derive(Parser, Debug)]
pub struct HostReprovisionSet {
    #[clap(short, long, help = "Machine ID for which reprovisioning is needed.")]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,

    #[clap(
        long,
        alias = "maintenance_reference",
        help = "If set, a HostUpdateInProgress health alert will be applied to the host"
    )]
    pub update_message: Option<String>,
}

#[derive(Parser, Debug)]
pub struct HostReprovisionClear {
    #[clap(
        short,
        long,
        help = "Machine ID for which reprovisioning should be cleared."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub enum ExpectedMachineAction {
    #[clap(about = "Show expected machine data")]
    Show(ShowExpectedMachineQuery),
    #[clap(about = "Add expected machine")]
    Add(ExpectedMachine),
    #[clap(about = "Delete expected machine")]
    Delete(DeleteExpectedMachine),
    #[clap(about = "Update expected machine")]
    Update(UpdateExpectedMachine),
    /// Replace all entries in the expected machines table with the entries from an inputted json file.
    ///
    /// Example json file:
    ///    {
    ///        "expected_machines":
    ///        [
    ///            {
    ///                "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-1"
    ///            },
    ///            {
    ///                "bmc_mac_address": "2a:2b:2c:2d:2e:2f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-2",
    ///                "fallback_dpu_serial_numbers": ["MT020100000003"],
    ///                "metadata": {
    ///                    "name": "MyMachine",
    ///                    "description": "My Machine",
    ///                    "labels": [{"key": "ABC", "value: "DEF"}]
    ///                }
    ///            }
    ///        ]
    ///    }
    #[clap(verbatim_doc_comment)]
    ReplaceAll(ExpectedMachineReplaceAllRequest),
    #[clap(about = "Erase all expected machines")]
    Erase,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct ExpectedMachine {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected machine")]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected machine")]
    pub bmc_username: String,
    #[clap(short = 'p', long, help = "BMC password of the expected machine")]
    pub bmc_password: String,
    #[clap(
        short = 's',
        long,
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: String,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Machines. If empty, the MachineId will be used"
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Machines"
    )]
    pub meta_description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A label that will be added as metadata for the newly created Machine. The labels key and value must be separated by a : character. E.g. DATACENTER:XYZ",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long = "sku-id",
        value_name = "SKU_ID",
        help = "A SKU ID that will be added for the newly created Machine."
    )]
    pub sku_id: Option<String>,
}

impl ExpectedMachine {
    pub fn metadata(&self) -> Result<::rpc::forge::Metadata, eyre::Report> {
        let mut labels = Vec::new();
        if let Some(list) = &self.labels {
            for label in list {
                let label = match label.split_once(':') {
                    Some((k, v)) => rpc::forge::Label {
                        key: k.trim().to_string(),
                        value: Some(v.trim().to_string()),
                    },
                    None => rpc::forge::Label {
                        key: label.trim().to_string(),
                        value: None,
                    },
                };
                labels.push(label);
            }
        }

        Ok(::rpc::forge::Metadata {
            name: self.meta_name.clone().unwrap_or_default(),
            description: self.meta_description.clone().unwrap_or_default(),
            labels,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedMachineJson {
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub chassis_serial_number: String,
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub sku_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedMachineMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub labels: HashMap<String, Option<String>>,
}

impl ExpectedMachine {
    pub fn has_duplicate_dpu_serials(&self) -> bool {
        match self.fallback_dpu_serial_numbers.clone() {
            Some(fallback_dpu_serial_numbers) => has_duplicates(fallback_dpu_serial_numbers),
            None => false,
        }
    }
}
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"chassis_serial_number",
"fallback_dpu_serial_numbers",
"sku_id",
])))]
pub struct UpdateExpectedMachine {
    #[clap(
        short = 'a',
        required = true,
        long,
        help = "BMC MAC Address of the expected machine"
    )]
    pub bmc_mac_address: MacAddress,
    #[clap(
        short = 'u',
        long,
        group = "group",
        requires("bmc_password"),
        help = "BMC username of the expected machine"
    )]
    pub bmc_username: Option<String>,
    #[clap(
        short = 'p',
        long,
        group = "group",
        requires("bmc_username"),
        help = "BMC password of the expected machine"
    )]
    pub bmc_password: Option<String>,
    #[clap(
        short = 's',
        long,
        group = "group",
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: Option<String>,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        group = "group",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,

    #[clap(
        long = "meta-name",
        value_name = "META_NAME",
        help = "The name that should be used as part of the Metadata for newly created Machines. If empty, the MachineId will be used"
    )]
    pub meta_name: Option<String>,

    #[clap(
        long = "meta-description",
        value_name = "META_DESCRIPTION",
        help = "The description that should be used as part of the Metadata for newly created Machines"
    )]
    pub meta_description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A label that will be added as metadata for the newly created Machine. The labels key and value must be separated by a : character",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "SKU_ID",
        group = "group",
        help = "A SKU ID that will be added for the newly created Machine."
    )]
    pub sku_id: Option<String>,
}

impl UpdateExpectedMachine {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.chassis_serial_number.is_none()
            && self.fallback_dpu_serial_numbers.is_none()
            && self.sku_id.is_none()
        {
            return Err("One of the following options must be specified: bmc-user-name and bmc-password or chassis-serial-number or fallback-dpu-serial-number".to_string());
        }
        if let Some(dpu_serials) = self.fallback_dpu_serial_numbers.clone() {
            if has_duplicates(&dpu_serials) {
                return Err("Duplicate dpu serial numbers found".to_string());
            }
        }
        Ok(())
    }

    pub fn metadata(&self) -> Result<::rpc::forge::Metadata, eyre::Report> {
        let mut labels = Vec::new();
        if let Some(list) = &self.labels {
            for label in list {
                let label = match label.split_once(':') {
                    Some((k, v)) => rpc::forge::Label {
                        key: k.trim().to_string(),
                        value: Some(v.trim().to_string()),
                    },
                    None => rpc::forge::Label {
                        key: label.trim().to_string(),
                        value: None,
                    },
                };
                labels.push(label);
            }
        }

        Ok(::rpc::forge::Metadata {
            name: self.meta_name.clone().unwrap_or_default(),
            description: self.meta_description.clone().unwrap_or_default(),
            labels,
        })
    }
}

#[derive(Parser, Debug)]
pub struct DeleteExpectedMachine {
    #[clap(help = "BMC MAC address of the expected machine to delete.")]
    pub bmc_mac_address: MacAddress,
}

#[derive(Parser, Debug)]
pub struct ShowExpectedMachineQuery {
    #[clap(
        default_value(None),
        help = "BMC MAC address of the expected machine to show. Leave unset for all."
    )]
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct ExpectedMachineReplaceAllRequest {
    #[clap(short, long)]
    pub filename: String,
}

#[derive(Parser, Debug)]
pub struct AgentUpgrade {
    #[clap(long)]
    pub set: Option<AgentUpgradePolicyChoice>,
}

// Should match api/src/model/machine/upgrade_policy.rs AgentUpgradePolicy
#[derive(ValueEnum, Debug, Clone)]
pub enum AgentUpgradePolicyChoice {
    Off,
    UpOnly,
    UpDown,
}

impl fmt::Display for AgentUpgradePolicyChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // enums are a special case where their debug impl is their name ("Off")
        fmt::Debug::fmt(self, f)
    }
}

// From the RPC
impl From<i32> for AgentUpgradePolicyChoice {
    fn from(rpc_policy: i32) -> Self {
        use rpc::forge::AgentUpgradePolicy::*;
        match rpc_policy {
            n if n == Off as i32 => AgentUpgradePolicyChoice::Off,
            n if n == UpOnly as i32 => AgentUpgradePolicyChoice::UpOnly,
            n if n == UpDown as i32 => AgentUpgradePolicyChoice::UpDown,
            _ => {
                unreachable!();
            }
        }
    }
}

#[derive(Parser, Debug)]
pub enum BootOverrideAction {
    Get(BootOverride),
    Set(BootOverrideSet),
    Clear(BootOverride),
}

#[derive(Parser, Debug)]
pub struct BootOverride {
    pub interface_id: String,
}

#[derive(Parser, Debug)]
pub struct BootOverrideSet {
    pub interface_id: String,
    #[clap(short = 'p', long)]
    pub custom_pxe: Option<String>,
    #[clap(short = 'u', long)]
    pub custom_user_data: Option<String>,
}

#[derive(Parser, Debug)]
pub enum NetworkDeviceAction {
    Show(NetworkDeviceShow),
}

#[derive(Parser, Debug)]
pub struct NetworkDeviceShow {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "id",
        help = "Show all network devices (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "Show data for the given network device (e.g. `mac=<mac>`), leave empty for all (default)"
    )]
    pub id: String,
}

#[derive(Parser, Debug)]
pub enum IpAction {
    Find(IpFind),
}

#[derive(Parser, Debug)]
pub struct IpFind {
    /// The IP address we are looking to identify
    pub ip: std::net::Ipv4Addr,
}

#[derive(Parser, Debug, Clone)]
pub struct RedfishAction {
    #[clap(subcommand)]
    pub command: RedfishCommand,

    #[clap(
        long,
        global = true,
        help = "IP:port of machine BMC. Port is optional and defaults to 443"
    )]
    pub address: Option<String>,

    #[clap(long, global = true, help = "Username for machine BMC")]
    pub username: Option<String>,

    #[clap(long, global = true, help = "Password for machine BMC")]
    pub password: Option<String>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum RedfishCommand {
    /// List BIOS attributes
    BiosAttrs,
    /// Set hard drive first in boot order
    BootHdd,
    /// Set PXE first in boot order
    BootPxe,
    /// Set Boot order to UEFI Http First
    BootUefiHttp,
    /// On next boot only, boot from hard drive
    BootOnceHdd,
    /// On next boot only, boot from PXE
    BootOncePxe,
    /// Boot rom UEFI HTTP Once
    BootOnceUefiHttp,
    /// Delete all pending jobs
    ClearPending,
    /// Create new BMC user
    CreateBmcUser(BmcUser),
    /// Create new BMC user
    DeleteBmcUser(DeleteBmcUser),
    /// Setup host for Forge use
    ForgeSetup(ForgeSetupArgs),
    /// Is everything ForgeSetup does already done? What's missing?
    ForgeSetupStatus,
    /// Set our password policy
    SetForgePasswordPolicy,
    /// List one or all BIOS boot options
    GetBootOption(BootOptionSelector),
    /// Is this thing on?
    GetPowerState,
    /// Disable BMC/BIOS lockdown
    LockdownDisable,
    /// Enable BMC/BIOS lockdown
    LockdownEnable,
    /// Display status of BMC/BIOS lockdown
    LockdownStatus,
    /// Force turn machine off
    #[clap(alias = "off", verbatim_doc_comment)]
    ForceOff,
    /// Force restart. This is equivalent to pressing the reset button on the front panel.
    /// - Will not restart DPUs
    /// - Will apply pending BIOS/UEFI setting changes
    #[clap(alias = "reset", verbatim_doc_comment)]
    ForceRestart,
    /// Graceful restart. Asks the OS to restart via ACPI
    /// - Might restart DPUs if no OS is running
    /// - Will not apply pending BIOS/UEFI setting changes
    #[clap(alias = "restart", verbatim_doc_comment)]
    GracefulRestart,
    /// Graceful host shutdown
    #[clap(alias = "shutdown", verbatim_doc_comment)]
    GracefulShutdown,
    /// AC power cycle
    ACPowerCycle,
    /// Power on a machine
    On,
    /// List PCIe devices
    PcieDevices,
    /// List Direct Attached drives
    LocalStorage,
    /// List pending operations
    Pending,
    /// Display power metrics (voltages, power supplies, etc)
    PowerMetrics,
    /// Enable serial console
    SerialEnable,
    /// Serial console status
    SerialStatus,
    /// Display thermal metrics (fans and temperatures)
    ThermalMetrics,
    /// Clear Trusted Platform Module (TPM)
    TpmReset,
    /// Reset BMC to factory defaults
    BmcResetToDefaults,
    /// Reboot the BMC itself
    BmcReset,
    /// Get Secure boot status
    GetSecureBoot,
    /// Disable Secure Boot
    DisableSecureBoot,
    /// List Chassis
    GetChassisAll,
    // List Chassis Subsystem
    GetChassis(Chassis),
    /// Show BMC's Ethernet interface information
    GetBmcEthernetInterfaces,
    /// Show System Ethernet interface information
    GetSystemEthernetInterfaces,
    /// List of existing BMC accounts
    GetBmcAccounts,
    /// Rename an account
    ChangeBmcUsername(BmcUsername),
    /// Change password for a BMC user
    ChangeBmcPassword(BmcPassword),
    /// Change UEFI password
    ChangeUefiPassword(UefiPassword),
    #[clap(about = "DPU specific operations", subcommand)]
    Dpu(DpuOperations),
    GetManager,
    /// Update host firmware
    UpdateFirmwareMultipart(Multipart),
    // Get detailed info on a Redfish task
    GetTask(Task),
    // Get a list of Redfish tasks
    GetTasks,
    /// Clear UEFI password
    ClearUefiPassword(UefiPassword),
    // Is IPMI enabled over LAN
    IsIpmiOverLanEnabled,
    // Enable IPMI over LAN
    EnableIpmiOverLan,
    // Disable IPMI over LAN
    DisableIpmiOverLan,
    // Get Base Mac Address (DPU only)
    GetBaseMacAddress,
    // Clear Nvram (Viking only)
    ClearNvram,
    // Redfish browser
    Browse(UriInfo),
    // Set BIOS options
    SetBios(SetBios),
    GetNicMode,
    IsInfiniteBootEnabled,
    SetNicMode,
    SetDpuMode,
    ChassisResetCard1Powercycle,
    SetBootOrderDpuFirst(SetBootOrderDpuFirstArgs),
    GetHostRshim,
    EnableHostRshim,
    DisableHostRshim,
    GetBossController,
    DecomissionController(DecomissionControllerArgs),
    CreateVolume(CreateVolumeArgs),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UriInfo {
    #[clap(long, help = "Redfish URI")]
    pub uri: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(group(ArgGroup::new("selector").required(true).args(&["all", "id"])))]
pub struct BootOptionSelector {
    #[clap(long)]
    pub all: bool,
    #[clap(long)]
    pub id: Option<String>,
}

#[derive(clap::Parser, Debug, PartialEq, Clone)]
pub enum DpuOperations {
    /// BMC's FW Commands
    #[clap(visible_alias = "fw", about = "BMC's FW Commands", subcommand)]
    Firmware(FwCommand),
    /// Show ports information
    Ports(ShowPort),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub enum FwCommand {
    /// Print FW update status
    Status,
    /// Update BMC's FW to the given FW package
    Update(FwPackage),
    /// Show FW versions of different components
    Show(ShowFw),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct FwPackage {
    #[clap(short, long, help = "FW package to install")]
    pub package: PathBuf,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UefiPassword {
    #[clap(long, help = "Current UEFI password")]
    pub current_password: String,
    #[clap(long, help = "New UEFI password")]
    pub new_password: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcUsername {
    #[clap(long, help = "Old username")]
    pub old_user: String,
    #[clap(long, help = "New username")]
    pub new_user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcPassword {
    #[clap(long, help = "New BMC password")]
    pub new_password: String,
    #[clap(long, help = "BMC user")]
    pub user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Multipart {
    #[clap(long, help = "Local filename for the firmware to be installed")]
    pub filename: String,
    #[clap(
        long,
        help = "Firmware type, ignored by some platforms and optional on others"
    )]
    pub component_type: Option<ComponentType>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Task {
    #[clap(long, help = "Task ID")]
    pub taskid: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Chassis {
    #[clap(long, help = "Chassis ID")]
    pub chassis_id: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcUser {
    #[clap(long, help = "BMC password")]
    pub new_password: String,
    #[clap(long, help = "BMC user")]
    pub user: String,
    #[clap(
        long,
        help = "BMC role (administrator, operator, readonly, noaccess). Default to administrator"
    )]
    pub role_id: Option<String>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct DeleteBmcUser {
    #[clap(long, help = "BMC user")]
    pub user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct ForgeSetupArgs {
    #[clap(long, help = "boot_interface_mac")]
    pub boot_interface_mac: Option<String>,
    #[clap(long, help = "BIOS profile config in JSON format")]
    pub bios_profiles: Option<String>,
    #[clap(long, help = "BIOS profile to use")]
    pub selected_profile: Option<libredfish::BiosProfileType>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct SetBootOrderDpuFirstArgs {
    #[clap(long, help = "boot_interface_mac")]
    pub boot_interface_mac: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct DecomissionControllerArgs {
    #[clap(long, help = "controller_id")]
    pub controller_id: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct CreateVolumeArgs {
    #[clap(long, help = "controller_id")]
    pub controller_id: String,
    #[clap(long, help = "volume_name")]
    pub volume_name: String,
    #[clap(long, help = "raid_type")]
    pub raid_type: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(group(
        ArgGroup::new("show_fw")
        .required(true)
        .args(&["all", "bmc", "dpu_os", "uefi", "fw"])))]
pub struct ShowFw {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "fw",
        help = "Show all discovered firmware key/values"
    )]
    pub all: bool,

    #[clap(long, action, conflicts_with = "fw", help = "Show BMC FW Version")]
    pub bmc: bool,

    #[clap(
        long,
        action,
        conflicts_with = "fw",
        help = "Show DPU OS version (shortcut for `show DPU_OS`)"
    )]
    pub dpu_os: bool,

    #[clap(
        long,
        action,
        conflicts_with = "fw",
        help = "Show UEFI version (shortcut for `show DPU_UEFI`)"
    )]
    pub uefi: bool,

    #[clap(
        default_value(""),
        help = "The firmware type to query (e.g. DPU_OS, DPU_UEFI, DPU_NIC), leave empty for all (default)"
    )]
    pub fw: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct ShowPort {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "port",
        help = "Show all ports (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The port to query (e.g. eth0, eth1), leave empty for all (default)"
    )]
    pub port: String,
}

#[derive(Parser, Debug)]
pub enum Machine {
    #[clap(about = "Display Machine information")]
    Show(ShowMachine),
    #[clap(about = "Print DPU admin SSH username:password")]
    DpuSshCredentials(MachineQuery),
    #[clap(subcommand, about = "Networking information")]
    Network(NetworkCommand),
    #[clap(
        about = "Health override related handling",
        subcommand,
        visible_alias = "ho"
    )]
    HealthOverride(OverrideCommand),
    #[clap(about = "Reboot a machine")]
    Reboot(BMCConfigForReboot),
    #[clap(about = "Force delete a machine")]
    ForceDelete(ForceDeleteMachineQuery),
    #[clap(about = "Set individual machine firmware autoupdate (host only)")]
    AutoUpdate(MachineAutoupdate),
    #[clap(subcommand, about = "Edit Metadata associated with a Machine")]
    Metadata(MachineMetadataCommand),
    #[clap(subcommand, about = "Update/show machine hardware info")]
    HardwareInfo(MachineHardwareInfoCommand),
}

#[derive(Parser, Debug)]
pub enum NetworkCommand {
    #[clap(about = "Print network status of all machines")]
    Status,
    #[clap(about = "Machine network configuration, used by VPC.")]
    Config(NetworkConfigQuery),
}

#[derive(Parser, Debug)]
pub enum OverrideCommand {
    #[clap(about = "List the health reports overrides")]
    Show { machine_id: String },
    #[clap(about = "Insert a health report override")]
    Add(HealthAddOptions),
    #[clap(about = "Print a empty health override template, which user can modify and use")]
    PrintEmptyTemplate,
    #[clap(about = "Remove a health report override")]
    Remove {
        machine_id: String,
        report_source: String,
    },
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("override_health").required(true).args(&["health_report", "template"])))]
pub struct HealthAddOptions {
    pub machine_id: String,
    #[clap(long, help = "New health report as json")]
    pub health_report: Option<String>,
    #[clap(
        long,
        help = "Predefined Template name. Use host-update for DPU Reprovision"
    )]
    pub template: Option<HealthOverrideTemplates>,
    #[clap(long, help = "Message to be filled in template.")]
    pub message: Option<String>,
    #[clap(long, help = "Replace all other health reports with this override")]
    pub replace: bool,
    #[clap(long, help = "Print the template that is going to be send to carbide")]
    pub print_only: bool,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum HealthOverrideTemplates {
    HostUpdate,
    InternalMaintenance,
    OutForRepair,
    Degraded,
    Validation,
    SuppressExternalAlerting,
    MarkHealthy,
    StopRebootForAutomaticRecoveryFromStateMachine,
    TenantReportedIssue,
    RequestRepair,
}

#[derive(Parser, Debug)]
pub enum ManagedHost {
    #[clap(about = "Display managed host information")]
    Show(ShowManagedHost),
    #[clap(
        about = "Switch a machine in/out of maintenance mode",
        subcommand,
        visible_alias = "fix"
    )]
    Maintenance(MaintenanceAction),
    #[clap(
        about = "Quarantine a host (disabling network access on host)",
        subcommand
    )]
    Quarantine(QuarantineAction),
    #[clap(about = "Reset host reprovisioning back to CheckingFirmware")]
    ResetHostReprovisioning(ResetHostReprovisioning),
    #[clap(subcommand, about = "Power Manager related settings.")]
    PowerOptions(PowerOptions),
}

#[derive(Parser, Debug)]
pub enum PowerOptions {
    Show(ShowPowerOptions),
    Update(UpdatePowerOptions),
}

#[derive(Parser, Debug)]
pub struct ShowPowerOptions {
    #[clap(help = "ID of the host or nothing for all")]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
pub struct UpdatePowerOptions {
    #[clap(help = "ID of the host")]
    pub machine: String,
    #[clap(long, short, help = "Desired Power State")]
    pub desired_power_state: DesiredPowerState,
}

#[derive(ValueEnum, Parser, Debug, Clone, PartialEq)]
pub enum DesiredPowerState {
    On,
    Off,
    PowerManagerDisabled,
}

#[derive(Parser, Debug)]
pub struct BMCConfigForReboot {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
}

#[derive(Parser, Debug)]
pub struct BMCIdentify {
    #[clap(long, help = "Hostname or IP of machine BMC")]
    pub address: String,
}

#[derive(Parser, Debug)]
pub struct BmcResetArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(short, long, help = "Use ipmitool")]
    pub use_ipmitool: bool,
}

#[derive(Parser, Debug)]
pub struct AdminPowerControlArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(long, help = "Power control action")]
    pub action: AdminPowerControlAction,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum AdminPowerControlAction {
    On,
    GracefulShutdown,
    ForceOff,
    GracefulRestart,
    ForceRestart,
    ACPowercycle,
}

impl From<AdminPowerControlAction> for rpc::forge::admin_power_control_request::SystemPowerControl {
    fn from(c_type: AdminPowerControlAction) -> Self {
        match c_type {
            AdminPowerControlAction::On => {
                rpc::forge::admin_power_control_request::SystemPowerControl::On
            }
            AdminPowerControlAction::GracefulShutdown => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulShutdown
            }
            AdminPowerControlAction::ForceOff => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff
            }
            AdminPowerControlAction::GracefulRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulRestart
            }
            AdminPowerControlAction::ForceRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart
            }
            AdminPowerControlAction::ACPowercycle => {
                rpc::forge::admin_power_control_request::SystemPowerControl::AcPowercycle
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct MachineQuery {
    #[clap(
        short,
        long,
        help = "ID, IPv4, MAC or hostnmame of the machine to query"
    )]
    pub query: String,
}

#[derive(Parser, Debug, Clone)]
pub enum MachineMetadataCommand {
    #[clap(about = "Set the Name or Description of the Machine")]
    Set(MachineMetadataCommandSet),
    #[clap(about = "Show the Metadata of the Machine")]
    Show(MachineMetadataCommandShow),
    #[clap(about = "Adds a label to the Metadata of a Machine")]
    AddLabel(MachineMetadataCommandAddLabel),
    #[clap(about = "Removes labels from the Metadata of a Machine")]
    RemoveLabels(MachineMetadataCommandRemoveLabels),
    #[clap(about = "Copy Machine Metadata from Expected-Machine to Machine")]
    FromExpectedMachine(MachineMetadataCommandFromExpectedMachine),
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandShow {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: String,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandSet {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: String,
    #[clap(long, help = "The updated name of the Machine")]
    pub name: Option<String>,
    #[clap(long, help = "The updated description of the Machine")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandAddLabel {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: String,
    #[clap(long, help = "The key to add")]
    pub key: String,
    #[clap(long, help = "The optional value to add")]
    pub value: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandRemoveLabels {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: String,
    #[clap(long, help = "The keys to remove")]
    pub keys: Vec<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandFromExpectedMachine {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: String,
    /// Whether to fully replace the Metadata that is currently stored on the Machine.
    /// - If not set, existing Metadata on the Machine will not be touched by executing
    ///   the command:
    ///   - The existing Name will not be changed if the Name is not equivalent
    ///     to the Machine ID or Empty.
    ///   - The existing Description will not be changed if it is not empty.
    ///   - Existing Labels and their values will not be changed. Only labels which
    ///     do not exist on the Machine will be added.
    /// - If set, the Machines Metadata will be set to the same values as
    ///   they would if the Machine would get freshly ingested.
    ///   Metadata that is currently set on the Machine will be overridden.
    #[clap(long, verbatim_doc_comment)]
    pub replace_all: bool,
}

#[derive(Parser, Debug)]
pub enum MachineHardwareInfoCommand {
    #[clap(about = "Show the hardware info of the machine")]
    Show(ShowMachineHardwareInfo),
    #[clap(subcommand, about = "Update the hardware info of the machine")]
    Update(MachineHardwareInfo),
}

#[derive(Parser, Debug)]
pub struct ShowMachineHardwareInfo {
    #[clap(long, help = "Show the hardware info of this Machine ID")]
    pub machine: String,
}

#[derive(Parser, Debug)]
pub enum MachineHardwareInfo {
    //Cpu(MachineTopologyCommandCpu),
    #[clap(about = "Update the GPUs of this machine")]
    Gpus(MachineHardwareInfoGpus),
    //Memory(MachineTopologyCommandMemory),
    //Storage(MachineTopologyCommandStorage),
    //Network(MachineTopologyCommandNetwork),
    //Infiniband(MachineTopologyCommandInfiniband),
    //Dpu(MachineTopologyCommandDpu),
}

#[derive(Parser, Debug)]
pub struct MachineHardwareInfoGpus {
    #[clap(long, help = "Machine ID of the server containing the GPUs")]
    pub machine: String,
    #[clap(
        long,
        help = "JSON file containing GPU info. It should contain an array of JSON objects like this:
        {
            \"name\": \"string\",
            \"serial\": \"string\",
            \"driver_version\": \"string\",
            \"vbios_version\": \"string\",
            \"inforom_version\": \"string\",
            \"total_memory\": \"string\",
            \"frequency\": \"string\",
            \"pci_bus_id\": \"string\"
        }
        Pass an empty array if you want to remove GPUs."
    )]
    pub gpu_json_file: std::path::PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub struct ForceDeleteMachineQuery {
    #[clap(
        long,
        help = "UUID, IPv4, MAC or hostnmame of the host or DPU machine to delete"
    )]
    pub machine: String,

    #[clap(
        short = 'd',
        long,
        action,
        help = "Delete interfaces. Redeploy kea after deleting machine interfaces."
    )]
    pub delete_interfaces: bool,

    #[clap(
        short = 'b',
        long,
        action,
        help = "Delete BMC interfaces. Redeploy kea after deleting machine interfaces."
    )]
    pub delete_bmc_interfaces: bool,

    #[clap(
        short = 'c',
        long,
        action,
        help = "Delete BMC credentials. Only applicable if site explorer has configured credentials for the BMCs associated with this managed host."
    )]
    pub delete_bmc_credentials: bool,

    #[clap(
        long,
        action,
        help = "Delete machine with allocated instance. This flag acknowledges destroying the user instance as well."
    )]
    pub allow_delete_with_instance: bool,
}

#[derive(Parser, Debug, Clone)]
#[clap(group(ArgGroup::new("autoupdate_action").required(true).args(&["enable", "disable", "clear"])))]
pub struct MachineAutoupdate {
    #[clap(long, help = "Machine ID of the host to change")]
    pub machine: MachineId,
    #[clap(
        short = 'e',
        long,
        action,
        help = "Enable auto updates even if globally disabled or individually disabled by config files"
    )]
    pub enable: bool,
    #[clap(
        short = 'd',
        long,
        action,
        help = "Disable auto updates even if globally enabled or individually enabled by config files"
    )]
    pub disable: bool,
    #[clap(
        short = 'c',
        long,
        action,
        help = "Perform auto updates according to config files"
    )]
    pub clear: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct NetworkConfigQuery {
    #[clap(long, required(true), help = "DPU machine id")]
    pub machine_id: String,
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowMachine {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    pub help: Option<bool>,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show all machines (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only DPUs"
    )]
    pub dpus: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only hosts"
    )]
    pub hosts: bool,

    #[clap(
        short = 't',
        long,
        action,
        // DPUs don't get associated with instance types.
        // Wouldn't hurt to allow the query, but might as well
        // be helpful here.
        conflicts_with = "dpus",
        help = "Show only machines for this instance type"
    )]
    pub instance_type_id: Option<String>,

    #[clap(
        default_value(""),
        help = "The machine to query, leave empty for all (default)"
    )]
    pub machine: String,

    #[clap(
        short = 'c',
        long,
        default_value("5"),
        help = "History count. Valid if `machine` argument is passed."
    )]
    pub history_count: u32,
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowManagedHost {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(
        short,
        long,
        action,
        help = "Show all managed hosts (DEPRECATED)",
        conflicts_with = "machine"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "Show managed host specific details (using host or dpu machine id), leave empty for all"
    )]
    pub machine: String,

    #[clap(
        short,
        long,
        action,
        help = "Show IP details in summary",
        conflicts_with = "machine"
    )]
    pub ips: bool,

    #[clap(
        short = 't',
        long,
        action,
        help = "Show only hosts for this instance type"
    )]
    pub instance_type_id: Option<String>,

    #[clap(
        short,
        long,
        action,
        help = "Show GPU and memory details in summary",
        conflicts_with = "machine"
    )]
    pub more: bool,

    #[clap(long, action, help = "Show only hosts in maintenance mode")]
    pub fix: bool,

    #[clap(long, action, help = "Show only hosts in quarantine")]
    pub quarantine: bool,
}

/// Enable or disable maintenance mode on a managed host.
/// To list machines in maintenance mode use `forge-admin-cli mh show --all --fix`
#[derive(Parser, Debug)]
pub enum MaintenanceAction {
    /// Put this machine into maintenance mode. Prevents an instance being assigned to it.
    On(MaintenanceOn),
    /// Return this machine to normal operation.
    Off(MaintenanceOff),
}

/// Enable or disable quarantine mode on a managed host.
#[derive(Parser, Debug)]
pub enum QuarantineAction {
    /// Put this machine into quarantine. Prevents any network access on the host machine.
    On(QuarantineOn),
    /// Take this machine out of quarantine
    Off(QuarantineOff),
}

/// Reset host reprovisioning state
#[derive(Parser, Debug)]
pub struct ResetHostReprovisioning {
    #[clap(long, required(true), help = "Machine ID to reset host reprovision on")]
    pub machine: String,
}

#[derive(Parser, Debug)]
pub struct QuarantineOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,

    #[clap(
        long,
        visible_alias = "reason",
        required(true),
        help = "Reason for quarantining this host"
    )]
    pub reason: String,
}

#[derive(Parser, Debug)]
pub struct QuarantineOff {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,
}

#[derive(Parser, Debug)]
pub struct MaintenanceOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,

    #[clap(
        long,
        visible_alias = "ref",
        required(true),
        help = "URL of reference (ticket, issue, etc) for this machine's maintenance"
    )]
    pub reference: String,
}

#[derive(Parser, Debug)]
pub struct MaintenanceOff {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,
}

#[derive(Parser, Debug)]
pub enum Instance {
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
    pub instance: String,

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
    pub machine: Option<String>,

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
    pub vpc_prefix_id: Vec<String>,

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
    pub vf_vpc_prefix_id: Vec<String>,

    #[clap(
        long,
        help = "The machine ids for the machines to use (instead of searching)"
    )]
    pub machine_id: Vec<MachineId>,
}

#[derive(Parser, Debug)]
pub struct UpdateInstanceOS {
    #[clap(short, long, required(true))]
    pub instance: String,
    #[clap(
        long,
        required(true),
        help = "OS definition in JSON format",
        value_name = "OS_JSON"
    )]
    pub os: OperatingSystem,
}

#[derive(Parser, Debug)]
pub enum Domain {
    #[clap(about = "Display Domain information")]
    Show(ShowDomain),
}

#[derive(Parser, Debug)]
pub struct ShowDomain {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "domain",
        help = "Show all domains (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The domain to query, leave empty for all (default)"
    )]
    pub domain: String,
}

#[derive(Parser, Debug)]
pub enum NetworkSegment {
    #[clap(about = "Display Network Segment information")]
    Show(ShowNetwork),
}

#[derive(Parser, Debug)]
pub struct ShowNetwork {
    #[clap(
        default_value(""),
        help = "The network segment to query, leave empty for all (default)"
    )]
    pub network: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,
}

impl CliOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[derive(Parser, Debug)]
pub enum ResourcePool {
    #[clap(
        about = "Add capacity to one or more resource pools from a TOML file. See carbide-api admin_grow_resource_pool docs for example TOML."
    )]
    Grow(ResourcePoolDefinition),
    #[clap(about = "List all resource pools with stats")]
    List,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("grow")
        .required(true)
        .args(&["filename"])))]
pub struct ResourcePoolDefinition {
    #[clap(short, long)]
    pub filename: String,
}

#[derive(Parser, Debug)]
pub enum BmcAction {
    #[clap(about = "Reset BMC")]
    BmcReset(BmcResetArgs),
    #[clap(about = "Redfish Power Control")]
    AdminPowerControl(AdminPowerControlArgs),
    CreateBmcUser(CreateBmcUserArgs),
    DeleteBmcUser(DeleteBmcUserArgs),
}

#[derive(Parser, Debug)]
pub enum CredentialAction {
    #[clap(about = "Add UFM credential")]
    AddUFM(AddUFMCredential),
    #[clap(about = "Delete UFM credential")]
    DeleteUFM(DeleteUFMCredential),
    #[clap(about = "Generate UFM credential")]
    GenerateUFMCert(GenerateUFMCertCredential),
    #[clap(about = "Add BMC credentials")]
    AddBMC(AddBMCredential),
    #[clap(about = "Delete BMC credentials")]
    DeleteBMC(DeleteBMCredential),
    #[clap(
        about = "Add site-wide DPU UEFI default credential (NOTE: this parameter can be set only once)"
    )]
    AddUefi(AddUefiCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for a given vendor")]
    AddHostFactoryDefault(AddHostFactoryDefaultCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for the DPUs")]
    AddDpuFactoryDefault(AddDpuFactoryDefaultCredential),
}

#[derive(Parser, Debug)]
pub struct AddUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,

    #[clap(long, default_value(""), help = "The UFM token")]
    pub token: String,
}

#[derive(Parser, Debug)]
pub struct DeleteUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,
}

#[derive(Parser, Debug)]
pub struct GenerateUFMCertCredential {
    #[clap(long, default_value_t = DEFAULT_IB_FABRIC_NAME.to_string(), help = "Infiniband fabric.")]
    pub fabric: String,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum BmcCredentialType {
    // Site Wide BMC Root Account Credentials
    SiteWideRoot,
    // BMC Specific Root Credentials
    BmcRoot,
    // BMC Specific Forge-Admin Credentials
    BmcForgeAdmin,
}

impl From<BmcCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: BmcCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            BmcCredentialType::SiteWideRoot => SiteWideBmcRoot,
            BmcCredentialType::BmcRoot => RootBmcByMacAddress,
            BmcCredentialType::BmcForgeAdmin => BmcForgeAdminByMacAddress,
        }
    }
}

#[derive(Parser, Debug)]
pub struct AddBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, required(true), help = "The password of BMC")]
    pub password: String,
    #[clap(long, help = "The username of BMC")]
    pub username: Option<String>,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct DeleteBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum UefiCredentialType {
    Dpu,
    Host,
}

impl From<UefiCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: UefiCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            UefiCredentialType::Dpu => DpuUefi,
            UefiCredentialType::Host => HostUefi,
        }
    }
}

#[derive(Parser, Debug)]
pub struct AddUefiCredential {
    #[clap(long, require_equals(true), required(true), help = "The UEFI kind")]
    pub kind: UefiCredentialType,

    #[clap(long, require_equals(true), help = "The UEFI password")]
    pub password: String,
}

#[derive(Parser, Debug)]
pub struct AddHostFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "Manufacturer default password")]
    pub password: String,
    #[clap(long, required(true))]
    pub vendor: bmc_vendor::BMCVendor,
}

#[derive(Parser, Debug)]
pub struct AddDpuFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "DPU manufacturer default password")]
    pub password: String,
}

#[derive(Parser, Debug)]
pub enum RouteServer {
    Get,
    Add(IpFind),
    Remove(IpFind),
}
#[derive(Parser, Debug)]
pub enum MachineInterfaces {
    #[clap(about = "List of all Machine interfaces")]
    Show(ShowMachineInterfaces),
    #[clap(about = "Delete Machine interface.")]
    Delete(DeleteMachineInterfaces),
}

#[derive(Parser, Debug)]
pub struct ShowMachineInterfaces {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "interface_id",
        help = "Show all machine interfaces (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The interface ID to query, leave empty for all (default)"
    )]
    pub interface_id: String,

    #[clap(long, action)]
    pub more: bool,
}

#[derive(Parser, Debug)]
pub struct DeleteMachineInterfaces {
    #[clap(help = "The interface ID to delete. Redeploy kea after deleting machine interfaces.")]
    pub interface_id: String,
}

#[derive(Parser, Debug)]
pub enum SiteExplorer {
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
    #[clap(flatten)]
    pub timeout_config: Option<TimeoutConfig>,
}

#[derive(Parser, Debug)]
pub struct CreateBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to create a new user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to create a new user")]
    pub mac_address: Option<MacAddress>,
    #[clap(
        long,
        short,
        help = "ID of the machine where we want to create a new user"
    )]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of new BMC account")]
    pub username: String,
    #[clap(long, short, help = "Password of new BMC account")]
    pub password: String,
    #[clap(
        long,
        short,
        help = "Role of new BMC account ('administrator', 'operator', 'readonly', 'noaccess')"
    )]
    pub role_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DeleteBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to delete a user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to delete a user")]
    pub mac_address: Option<MacAddress>,
    #[clap(long, short, help = "ID of the machine where we want to delete a user")]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of BMC account to delete")]
    pub username: String,
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
pub struct ShellCompleteAction {
    #[clap(subcommand)]
    pub shell: Shell,
}

#[derive(Parser, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum Shell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Parser, Debug)]
pub struct PingOptions {
    #[clap(
        short,
        long,
        default_value("1.0"),
        help = "Wait interval seconds between sending each request. Real number allowed with dot as a decimal separator."
    )]
    pub interval: f32,
}

#[derive(Parser, Debug)]
pub struct LogFilterOptions {
    #[clap(short, long, help = "Set server's RUST_LOG.")]
    pub filter: String,
    #[clap(
        long,
        default_value("1h"),
        help = "Revert to startup RUST_LOG after this much time, friendly format e.g. '1h', '3min', https://docs.rs/duration-str/latest/duration_str/"
    )]
    pub expiry: String,
}

#[derive(Parser, Debug)]
pub struct CreateMachinesOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer create_machines?")]
    pub enabled: bool,
}

#[derive(Parser, Debug)]
pub struct BmcProxyOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer bmc_proxy")]
    pub enabled: bool,
    #[clap(long, action = clap::ArgAction::Set, help = "host:port string use as a proxy for talking to BMC's")]
    pub proxy: Option<String>,
}

#[derive(Parser, Debug)]
pub enum VpcOptions {
    #[clap(about = "Display VPC information")]
    Show(ShowVpc),
    SetVirtualizer(SetVpcVirt),
}

#[derive(Parser, Debug)]
pub struct ShowVpc {
    #[clap(
        default_value(""),
        help = "The VPC ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,

    #[clap(long, help = "The key of VPC label to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of VPC label to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
pub struct SetVpcVirt {
    #[clap(help = "The VPC ID for the VPC to update")]
    pub id: String,
    #[clap(help = "The virtualizer to use for this VPC")]
    pub virtualizer: VpcVirtualizationType,
}

#[derive(Parser, Debug)]
pub enum VpcPeeringOptions {
    #[clap(about = "Create VPC peering.")]
    Create(VpcPeeringCreate),
    #[clap(about = "Show list of VPC peerings.")]
    Show(VpcPeeringShow),
    #[clap(about = "Delete VPC peering.")]
    Delete(VpcPeeringDelete),
}

#[derive(Parser, Debug)]
pub struct VpcPeeringCreate {
    #[clap(help = "The ID of one VPC ID to peer")]
    pub vpc1_id: VpcId,

    #[clap(help = "The ID of another one VPC ID to peer")]
    pub vpc2_id: VpcId,
}

#[derive(Parser, Debug)]
pub struct VpcPeeringShow {
    #[clap(
        long,
        conflicts_with = "vpc_id",
        help = "Search by ID of the VPC peering"
    )]
    pub id: Option<String>,

    #[clap(
        long,
        conflicts_with = "id",
        help = "Search by VPC ID to show list of related VPC peerings"
    )]
    pub vpc_id: Option<VpcId>,
}

#[derive(Parser, Debug)]
pub struct VpcPeeringDelete {
    #[clap(long, required(true), help = "The ID of the VPC peering to delete")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub enum VpcPrefixOptions {
    #[clap(hide = true)]
    Create(VpcPrefixCreate),
    Show(VpcPrefixShow),
    #[clap(hide = true)]
    Delete(VpcPrefixDelete),
}

#[derive(Parser, Debug)]
pub struct VpcPrefixCreate {
    #[clap(
        long,
        name = "vpc-id",
        value_name = "VpcId",
        help = "The ID of the VPC to contain this prefix"
    )]
    pub vpc_id: VpcId,

    #[clap(
        long,
        name = "prefix",
        value_name = "CIDR-prefix",
        help = "The IP prefix in CIDR notation"
    )]
    pub prefix: IpNet,

    #[clap(
        long,
        name = "name",
        value_name = "prefix-name",
        help = "A short descriptive name for the prefix"
    )]
    pub name: String,

    #[clap(
        long,
        name = "vpc-prefix-id",
        value_name = "VpcPrefixId",
        help = "Specify the VpcPrefixId for the API to use instead of it auto-generating one"
    )]
    pub vpc_prefix_id: Option<VpcPrefixId>,
}

#[derive(Parser, Debug)]
pub struct VpcPrefixShow {
    #[clap(
        name = "VpcPrefixSelector",
        help = "The VPC prefix (by ID or exact unique prefix) to show (omit for all)"
    )]
    pub prefix_selector: Option<VpcPrefixSelector>,

    #[clap(
        long,
        name = "vpc-id",
        value_name = "VpcId",
        help = "Search by VPC ID",
        conflicts_with = "VpcPrefixSelector"
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(
        long,
        name = "contains",
        value_name = "address-or-prefix",
        help = "Search by an address or prefix the VPC prefix contains",
        conflicts_with_all = ["VpcPrefixSelector", "contained-by"],
    )]
    pub contains: Option<IpNet>,

    #[clap(
        long,
        name = "contained-by",
        value_name = "prefix",
        help = "Search by a prefix containing the VPC prefix",
        conflicts_with_all = ["VpcPrefixSelector", "contains"],
    )]
    pub contained_by: Option<IpNet>,
}

#[derive(Parser, Debug)]
pub struct VpcPrefixDelete {
    #[clap(value_name = "VpcPrefixId")]
    pub vpc_prefix_id: VpcPrefixId,
}

#[derive(Parser, Debug)]
pub enum IbPartitionOptions {
    #[clap(about = "Display InfiniBand Partition information")]
    Show(ShowIbPartition),
}

#[derive(Parser, Debug)]
pub struct ShowIbPartition {
    #[clap(
        default_value(""),
        help = "The InfiniBand Partition ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The InfiniBand Partition name to query")]
    pub name: Option<String>,
}

#[derive(Parser, Debug)]
pub enum TenantKeySetOptions {
    #[clap(about = "Display Tenant KeySet information")]
    Show(ShowTenantKeySet),
}

#[derive(Parser, Debug)]
pub struct ShowTenantKeySet {
    #[clap(
        default_value(""),
        help = "The Tenant KeySet ID in the format of <tenant_org_id>/<keyset_id> to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct JumpOptions {
    #[clap(required(true), help = "The machine ID, IP, UUID, etc, to find")]
    pub id: String,
}
#[derive(Parser, Debug)]

pub enum MachineValidationCommand {
    #[clap(about = "External config", subcommand, visible_alias = "mve")]
    ExternalConfig(MachineValidationExternalConfigCommand),
    #[clap(about = "Ondemand Validation", subcommand, visible_alias = "mvo")]
    OnDemand(MachineValidationOnDemandCommand),
    #[clap(
        about = "Display machine validation results of individual runs",
        subcommand,
        visible_alias = "mvr"
    )]
    Results(MachineValidationResultsCommand),
    #[clap(
        about = "Display all machine validation runs",
        subcommand,
        visible_alias = "mvt"
    )]
    Runs(MachineValidationRunsCommand),
    #[clap(about = "Supported Tests ", subcommand, visible_alias = "mvs")]
    Tests(Box<MachineValidationTestsCommand>),
}
#[derive(Parser, Debug)]
pub enum MachineValidationExternalConfigCommand {
    #[clap(about = "Show External config")]
    Show(MachineValidationExternalConfigShowOptions),

    #[clap(about = "Update External config")]
    AddUpdate(MachineValidationExternalConfigAddOptions),

    #[clap(about = "Remove External config")]
    Remove(MachineValidationExternalConfigRemoveOptions),
}

#[derive(Parser, Debug)]
pub struct MachineValidationExternalConfigShowOptions {
    #[clap(short, long, help = "Machine validation external config names")]
    pub name: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct MachineValidationExternalConfigAddOptions {
    #[clap(short, long, help = "Name of the file to update")]
    pub file_name: String,
    #[clap(short, long, help = "Name of the config")]
    pub name: String,
    #[clap(short, long, help = "description of the file to update")]
    pub description: String,
}
#[derive(Parser, Debug)]
pub struct MachineValidationExternalConfigRemoveOptions {
    #[clap(short, long, help = "Machine validation external config name")]
    pub name: String,
}

#[derive(Parser, Debug)]
pub enum MachineValidationRunsCommand {
    #[clap(about = "Show Runs")]
    Show(ShowMachineValidationRunsOptions),
}

#[derive(Parser, Debug)]
pub struct ShowMachineValidationRunsOptions {
    #[clap(short = 'm', long, help = "Show machine validation runs of a machine")]
    pub machine: Option<String>,

    #[clap(long, default_value = "false", help = "run history")]
    pub history: bool,
}
#[derive(Parser, Debug)]
pub enum MachineValidationResultsCommand {
    #[clap(about = "Show results")]
    Show(ShowMachineValidationResultsOptions),
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
    "validation_id",
    "test_name",
    "machine",
    ])))]
pub struct ShowMachineValidationResultsOptions {
    #[clap(
        short = 'm',
        long,
        group = "group",
        help = "Show machine validation result of a machine"
    )]
    pub machine: Option<String>,

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
pub enum MachineValidationOnDemandCommand {
    #[clap(about = "Start on demand machine validation")]
    Start(MachineValidationOnDemandOptions),
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct MachineValidationOnDemandOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(short, long, help = "Machine id for start validation")]
    pub machine: String,

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
pub enum MachineValidationTestsCommand {
    #[clap(about = "Show tests")]
    Show(ShowMachineValidationTestOptions),
    #[clap(about = "Verify a given test")]
    Verify(MachineValidationVerifyTestOptions),
    #[clap(about = "Add new test case")]
    Add(MachineValidationAddTestOptions),
    #[clap(about = "Update existing test case")]
    Update(MachineValidationUpdateTestOptions),
    #[clap(about = "Enabled a test")]
    Enable(MachineValidationEnableDisableTestOptions),
    #[clap(about = "Disable a test")]
    Disable(MachineValidationEnableDisableTestOptions),
}

#[derive(Parser, Debug)]
pub struct ShowMachineValidationTestOptions {
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
pub struct MachineValidationVerifyTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}
#[derive(Parser, Debug)]
pub struct MachineValidationEnableDisableTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}

#[derive(Parser, Debug)]
pub struct MachineValidationUpdateTestOptions {
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
pub struct MachineValidationAddTestOptions {
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

#[derive(Parser, Debug, Clone, PartialEq)]
pub struct SetBios {
    #[clap(
        long,
        help = "BIOS attributes to set in JSON, ex: {\"OperatingModes_ChooseOperatingMode\": \"MaximumPerformance\"}"
    )]
    pub attributes: String,
}

#[derive(Parser, Debug)]
pub enum DevEnv {
    #[clap(about = "Config related handling", visible_alias = "c", subcommand)]
    Config(DevEnvConfig),
}

#[derive(Parser, Debug)]
pub enum DevEnvConfig {
    #[clap(about = "Apply devenv config", visible_alias = "a")]
    Apply(DevEnvApplyConfig),
}

#[derive(Parser, Debug)]
pub struct DevEnvApplyConfig {
    #[clap(
        help = "Path to devenv config file. Usually this is in forged repo at envs/local-dev/site/site-controller/files/generated/devenv_config.toml"
    )]
    pub path: String,

    #[clap(long, short, help = "Vpc prefix or network segment?")]
    pub mode: NetworkChoice,
}

#[derive(ValueEnum, Parser, Debug, Clone, PartialEq)]
pub enum NetworkChoice {
    NetworkSegment,
    VpcPrefix,
}

#[derive(Parser, Debug)]
pub enum Sku {
    #[clap(about = "Show SKU information", visible_alias = "s")]
    Show(ShowSku),
    #[clap(about = "Show what machines are assigned a SKU")]
    ShowMachines(ShowSku),
    #[clap(
        about = "Generate SKU information from an existing machine",
        visible_alias = "g"
    )]
    Generate(GenerateSku),
    #[clap(about = "Create SKUs from a file", visible_alias = "c")]
    Create(CreateSku),
    #[clap(about = "Delete a SKU", visible_alias = "d")]
    Delete { sku_id: String },
    #[clap(about = "Assign a SKU to a machine", visible_alias = "a")]
    Assign { sku_id: String, machine_id: String },
    #[clap(about = "Unassign a SKU from a machine", visible_alias = "u")]
    Unassign { machine_id: String },
    #[clap(about = "Verify a machine against its SKU", visible_alias = "v")]
    Verify { machine_id: String },
    #[clap(about = "Update the metadata of a SKU")]
    UpdateMetadata(UpdateSkuMetadata),
}

#[derive(Parser, Debug)]
pub enum SshActions {
    #[clap(about = "Show Rshim Status")]
    GetRshimStatus(SshArgs),
    #[clap(about = "Disable Rshim")]
    DisableRshim(SshArgs),
    #[clap(about = "EnableRshim")]
    EnableRshim(SshArgs),
    #[clap(about = "Copy BFB to the DPU BMC's RSHIM ")]
    CopyBfb(CopyBfbArgs),
    #[clap(about = "Show the DPU's BMC's OBMC log")]
    ShowObmcLog(SshArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct TimeoutConfig {
    #[clap(long, help = "TCP Connection Timeout (seconds)")]
    pub tcp_connection_timeout: Option<u64>,

    #[clap(long, help = "TCP Read Timeout (seconds)")]
    pub tcp_read_timeout: Option<u64>,

    #[clap(long, help = "TCP Write Timeout (seconds)")]
    pub tcp_write_timeout: Option<u64>,

    #[clap(long, help = "SSH Session Timeout (seconds)")]
    pub ssh_session_timeout: Option<u64>,
}

impl TimeoutConfig {
    pub fn to_ssh_config(&self) -> SshConfig {
        SshConfig {
            tcp_connection_timeout: DEFAULT_TCP_CONNECTION_TIMEOUT,
            tcp_read_timeout: DEFAULT_TCP_READ_TIMEOUT,
            tcp_write_timeout: DEFAULT_TCP_WRITE_TIMEOUT,
            ssh_session_timeout: DEFAULT_SSH_SESSION_TIMEOUT,
        }
    }

    pub fn to_rpc_timeout_config(&self) -> SshTimeoutConfig {
        SshTimeoutConfig {
            tcp_connection_timeout: self.tcp_connection_timeout,
            tcp_read_timeout: self.tcp_read_timeout,
            tcp_write_timeout: self.tcp_write_timeout,
            ssh_session_timeout: self.ssh_session_timeout,
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct BmcCredentials {
    #[clap(help = "BMC IP Address")]
    pub bmc_ip_address: SocketAddr,
    #[clap(help = "BMC Username")]
    pub bmc_username: String,
    #[clap(help = "BMC Password")]
    pub bmc_password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct SshArgs {
    #[clap(flatten)]
    pub credentials: BmcCredentials,
    #[clap(flatten)]
    pub timeouts: Option<TimeoutConfig>,
}

#[derive(Parser, Debug)]
pub struct CopyBfbArgs {
    #[clap(flatten)]
    pub ssh_args: SshArgs,
    #[clap(help = "BFB Path")]
    pub bfb_path: String,
}

#[derive(Parser, Debug)]
pub struct ShowSku {
    #[clap(help = "Show SKU details")]
    pub sku_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct GenerateSku {
    #[clap(help = "The filename of the SKU data")]
    pub machine_id: String,
    #[clap(help = "override the ID of the SKU", long)]
    pub id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct CreateSku {
    #[clap(help = "The filename of the SKU data")]
    pub filename: String,
    #[clap(help = "override the ID of the SKU", long)]
    pub id: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&["description", "device_type"])))]
pub struct UpdateSkuMetadata {
    #[clap(help = "SKU ID of the SKU to update")]
    pub sku_id: String,
    #[clap(help = "Update the SKU's description", long, group("group"))]
    pub description: Option<String>,
    #[clap(help = "Update the SKU's device type", long, group("group"))]
    pub device_type: Option<String>,
}

impl From<UpdateSkuMetadata> for ::rpc::forge::SkuUpdateMetadataRequest {
    fn from(value: UpdateSkuMetadata) -> Self {
        ::rpc::forge::SkuUpdateMetadataRequest {
            sku_id: value.sku_id,
            description: value.description,
            device_type: value.device_type,
        }
    }
}
