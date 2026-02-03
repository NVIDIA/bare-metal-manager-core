/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bmc_mock::{DpuMachineInfo, HostMachineInfo};
use carbide_uuid::machine::MachineId;
use clap::Parser;
use duration_str::deserialize_duration;
use mac_address::MacAddress;
use rpc::forge::DesiredFirmwareVersionEntry;
use rpc::forge_tls_client::ForgeClientConfig;
use rpc::protos::forge_api_client::ForgeApiClient;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::BmcRegistrationMode;
use crate::api_client::ApiClient;
use crate::api_throttler::ApiThrottler;
use crate::machine_state_machine::OsImage;

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(name = "machine-sim")]
pub struct MachineATronArgs {
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

    #[clap(
        help = "Machine-A-Tron config file",
        env = "MACHINE_A_TRON_CONFIG_PATH"
    )]
    pub config_file: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MachineConfig {
    pub host_count: u32,
    pub vpc_count: u32,
    pub subnets_per_vpc: u32,
    pub dpu_per_host_count: u32,
    pub boot_delay: u32,
    pub dpu_reboot_delay: u64,  // in units of seconds
    pub host_reboot_delay: u64, // in units of seconds
    #[serde(
        default = "default_scout_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub scout_run_interval: Duration,
    #[serde(default = "default_template_dir")]
    pub template_dir: String,
    pub oob_dhcp_relay_address: Ipv4Addr,
    pub admin_dhcp_relay_address: Ipv4Addr,

    #[serde(
        default = "default_run_interval_working",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval_working: Duration,
    #[serde(
        default = "default_run_interval_idle",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval_idle: Duration,
    #[serde(
        default = "default_network_status_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub network_status_run_interval: Duration,
    /// If true, DPUs will run in "nic mode" and will not PXE boot, and their BMC JSON will reflect as such
    #[serde(default)]
    pub dpus_in_nic_mode: bool,

    /// What firmware versions to report for DPUs in this host
    #[serde(default)]
    pub dpu_firmware_versions: Option<DpuFirmwareVersions>,

    #[serde(default)]
    pub dpu_agent_version: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct DpuFirmwareVersions {
    pub bmc: Option<String>,
    pub cec: Option<String>,
    pub uefi: Option<String>,
    pub nic: Option<String>,
}

/// BMC-mock has its own version of this data structure to avoid cyclic dependencies
impl From<DpuFirmwareVersions> for bmc_mock::DpuFirmwareVersions {
    fn from(value: DpuFirmwareVersions) -> Self {
        Self {
            bmc: value.bmc,
            cec: value.cec,
            uefi: value.uefi,
            nic: value.nic,
        }
    }
}

impl DpuFirmwareVersions {
    pub fn fill_missing_from_desired_firmware(
        self,
        desired_firmware: &[DesiredFirmwareVersionEntry],
    ) -> Self {
        // We emulate bf3 DPU's, find those from the desired firmware.
        let Some(bf3_firmware_map) = desired_firmware
            .iter()
            .find(|entry| {
                if entry.vendor != "nvidia" {
                    return false;
                }
                let normalized = entry.model.as_str().to_lowercase().replace("-", " ");
                normalized.contains("bluefield 3")
            })
            .map(|entry| &entry.component_versions)
        else {
            return self;
        };

        // Prefer onese we already have set, falling back on the server-wanted ones.
        Self {
            bmc: self.bmc.or_else(|| bf3_firmware_map.get("bmc").cloned()),
            cec: self.cec.or_else(|| bf3_firmware_map.get("cec").cloned()),
            uefi: self.uefi.or_else(|| bf3_firmware_map.get("uefi").cloned()),
            nic: self.nic.or_else(|| bf3_firmware_map.get("nic").cloned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MachineATronConfig {
    // note that order is important in machines so that mac addresses are assigned the same way between runs
    #[serde(
        deserialize_with = "deserialize_machine_config",
        serialize_with = "serialize_machine_config"
    )]
    pub machines: BTreeMap<String, Arc<MachineConfig>>,
    pub carbide_api_url: String,
    pub log_file: Option<String>,
    pub interface: String,
    #[serde(default = "default_true")]
    pub tui_enabled: bool,

    #[serde(default = "default_true")]
    pub use_dhcp_api: bool,
    pub dhcp_server_address: Option<String>,
    #[serde(default = "default_bmc_mock_port")]
    pub bmc_mock_port: u16,

    /// Set this to true if you want each mock machine to run a mock BMC ssh server. This is useful
    /// for testing things like ssh-console.
    #[serde(default = "default_false")]
    pub mock_bmc_ssh_server: bool,

    /// Set this to configure the port to use when mocking a BMC SSH server. If unset and
    /// use_single_bmc_mock is true, it will pick a random port. If unset and use_single_bmc_mock
    /// is false, it will use port 2222 for each IP alias. (Port 22 is problematic because it
    /// collides with any system SSH server.)
    #[serde(default)]
    pub mock_bmc_ssh_port: Option<u16>,

    /// Set this to true if all BMC-mocks should be behind a single address (using HTTP headers to
    /// proxy to the real mock). This is the case for machine-a-tron running inside kubernetes
    /// clusters where there is a single k8s Service and we can't dynamically assign IP's.
    #[serde(default = "default_false")]
    pub use_single_bmc_mock: bool,

    #[serde(default = "default_false")]
    pub use_pxe_api: bool,
    pub pxe_server_host: Option<String>,
    pub pxe_server_port: Option<String>,
    pub sudo_command: Option<String>,
    /// Set this to a hostname or IP If you want machine-a-tron to register its BMC-mock as the bmc_proxy host (this will be combined with bmc_mock_port.)
    pub configure_carbide_bmc_proxy_host: Option<String>,

    #[serde(default)]
    /// Set this to the path of a directory that can be used to persist machine info between runs
    pub persist_dir: Option<PathBuf>,

    #[serde(default)]
    /// Set this to true to delete created machines from the API on quit
    pub cleanup_on_quit: bool,

    /// How often to refresh the API state from the server. Longer durations are appropriate for
    /// mocking lots of hosts, shorter durations are appropriate for integration tests where the
    /// interval should be shorter than the state controller update interval
    #[serde(
        default = "default_api_refresh_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub api_refresh_interval: Duration,
}

impl MachineATronConfig {
    pub fn read_persisted_machines(
        &self,
    ) -> eyre::Result<Option<HashMap<String, Vec<PersistedHostMachine>>>> {
        let Some(machines_persist_dir) = &self.machines_persist_dir() else {
            return Ok(None);
        };

        let machines_by_config_section: HashMap<String, Vec<PersistedHostMachine>> =
            std::fs::read_dir(machines_persist_dir)?
                .map(|f| {
                    let f = f?;
                    let filename = f.file_name().to_string_lossy().into_owned();
                    let Some(config_section) = filename.strip_suffix(".json") else {
                        return Ok(None);
                    };
                    Ok(Some((
                        config_section.to_string(),
                        serde_json::from_reader(std::fs::File::open(f.path())?)?,
                    )))
                })
                // Ensure no errors
                .collect::<eyre::Result<Vec<_>>>()?
                // Drop None's
                .into_iter()
                .flatten()
                // Build the HashMap
                .collect();
        Ok(Some(machines_by_config_section))
    }

    pub fn write_persisted_machines(&self, machines: &[PersistedHostMachine]) -> eyre::Result<()> {
        let Some(machines_persist_dir) = &self.machines_persist_dir() else {
            return Ok(());
        };

        std::fs::create_dir_all(machines_persist_dir)?;

        let mut persisted_machines_by_section: HashMap<String, Vec<&PersistedHostMachine>> =
            HashMap::new();
        for machine in machines {
            if let Some(machines) =
                persisted_machines_by_section.get_mut(&machine.machine_config_section)
            {
                machines.push(machine);
            } else {
                persisted_machines_by_section
                    .insert(machine.machine_config_section.clone(), vec![machine]);
            }
        }

        for (config_section, persisted_machines) in persisted_machines_by_section {
            std::fs::write(
                machines_persist_dir.join(format!("{config_section}.json")),
                serde_json::to_vec(&persisted_machines)?,
            )?;
        }

        Ok(())
    }

    fn machines_persist_dir(&self) -> Option<PathBuf> {
        self.persist_dir.as_ref().map(|d| d.join("machines"))
    }
}

/// A subset of the information about a HostMachine which is persisted to JSON to be recovered in
/// subsequent runs of machine-a-tron.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedHostMachine {
    pub mat_id: Uuid,
    pub machine_config_section: String,
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<PersistedDpuMachine>,
    pub non_dpu_mac_address: Option<MacAddress>,
    pub observed_machine_id: Option<MachineId>,
    pub installed_os: OsImage,
    pub tpm_ek_certificate: Option<Vec<u8>>,
    pub machine_dhcp_id: Uuid,
    pub bmc_dhcp_id: Uuid,
}

impl From<PersistedHostMachine> for HostMachineInfo {
    fn from(value: PersistedHostMachine) -> Self {
        Self {
            bmc_mac_address: value.bmc_mac_address,
            serial: value.serial,
            dpus: value.dpus.into_iter().map(Into::into).collect(),
            non_dpu_mac_address: value.non_dpu_mac_address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedDpuMachine {
    pub mat_id: Uuid,
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
    pub nic_mode: bool,
    pub firmware_versions: bmc_mock::DpuFirmwareVersions,
    pub installed_os: OsImage,
    pub dpu_index: u8,
    pub machine_dhcp_id: Uuid,
    pub bmc_dhcp_id: Uuid,
}

impl From<PersistedDpuMachine> for DpuMachineInfo {
    fn from(value: PersistedDpuMachine) -> Self {
        Self {
            bmc_mac_address: value.bmc_mac_address,
            host_mac_address: value.host_mac_address,
            oob_mac_address: value.oob_mac_address,
            serial: value.serial,
            nic_mode: value.nic_mode,
            firmware_versions: value.firmware_versions,
        }
    }
}

fn default_bmc_mock_port() -> u16 {
    2000
}

fn default_template_dir() -> String {
    String::from("dev/machine-a-tron/templates")
}

fn default_run_interval_working() -> Duration {
    Duration::from_secs(5)
}

fn default_run_interval_idle() -> Duration {
    Duration::from_secs(30)
}

fn default_api_refresh_interval() -> Duration {
    Duration::from_secs(2)
}

fn default_network_status_run_interval() -> Duration {
    Duration::from_secs(20)
}

fn default_scout_run_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

// Lots of types keep an owned reference to MachineATronContext, making an Arc keeps this cheap.

#[derive(Debug)]
pub struct MachineATronContext {
    pub app_config: MachineATronConfig,
    pub forge_client_config: ForgeClientConfig,
    pub bmc_mock_certs_dir: Option<PathBuf>,
    pub bmc_registration_mode: BmcRegistrationMode,
    pub api_throttler: ApiThrottler,
    /// These are the firmware versions the server wants us to be on. If not configured for other
    /// firmware, DPU's can mock that they already have this installed.
    pub desired_firmware_versions: Vec<DesiredFirmwareVersionEntry>,
    pub forge_api_client: ForgeApiClient,
}

impl MachineATronContext {
    pub fn api_client(&self) -> ApiClient {
        self.forge_api_client.clone().into()
    }
}

fn as_std_duration<S>(d: &std::time::Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if d.lt(&Duration::from_secs(1)) {
        serializer.serialize_str(&format!("{}ms", d.as_millis()))
    } else {
        serializer.serialize_str(&format!("{}s", d.as_secs()))
    }
}

pub fn deserialize_machine_config<'a, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Arc<MachineConfig>>, D::Error>
where
    D: Deserializer<'a>,
{
    let result: BTreeMap<String, MachineConfig> = Deserialize::deserialize(deserializer)?;
    Ok(result.into_iter().map(|(k, v)| (k, v.into())).collect())
}

fn serialize_machine_config<S>(
    d: &BTreeMap<String, Arc<MachineConfig>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(d.len()))?;
    for (k, v) in d {
        map.serialize_entry(k, v.as_ref())?;
    }
    map.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_config() {
        let cfg_str = r#"
carbide_api_url = "https://carbide-api.forge:443"
log_file = "mat.log"
interface = "br-77cbb29de011"
tui_enabled = true
use_dhcp_api = true
dhcp_server_address = "192.168.176.5"
pxe_server_host = "192.168.176.7"
pxe_server_port = "8080"
bmc_mock_port = 1266
mat_api_server_enabled = true
mat_api_server_listen_port = 2112
use_single_bmc_mock = true
configure_carbide_bmc_proxy_host = "192.168.1.20"

[machines.config]
host_count = 10
dpu_per_host_count = 2
boot_delay = 1
dpu_reboot_delay = 1 # in units of seconds
host_reboot_delay = 1 # in units of seconds
vpc_count = 0
admin_dhcp_relay_address = "192.168.176.1"
oob_dhcp_relay_address = "192.168.192.1"
subnets_per_vpc = 0
run_interval_working = "100ms"
run_interval_idle = "1s"
network_status_run_interval = "5s"
scout_run_interval = "5s"
    "#;

        let cfg = toml::from_str::<MachineATronConfig>(cfg_str).expect("Could not parse config");
        let serialized = toml::to_string(&cfg).expect("Could not serialize config");
        let round_tripped = toml::from_str::<MachineATronConfig>(&serialized)
            .expect("Could not deserialize serialized config");
        assert_eq!(round_tripped, cfg);
    }
}
