use axum::Router;
use clap::Parser;
use duration_str::deserialize_duration;
use rpc::forge_tls_client::ForgeClientConfig;
use serde::{Deserialize, Serialize, Serializer};
use std::path::PathBuf;
use std::time::Duration;
use std::{collections::BTreeMap, net::Ipv4Addr};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineATronConfig {
    // note that order is important in machines so that mac addresses are assigned the same way between runs
    pub machines: BTreeMap<String, MachineConfig>,
    pub carbide_api_url: Option<String>,
    pub log_file: Option<String>,
    pub interface: String,
    #[serde(default = "default_true")]
    pub tui_enabled: bool,

    #[serde(default = "default_true")]
    pub use_dhcp_api: bool,
    pub dhcp_server_address: Option<String>,
    #[serde(default = "default_bmc_mock_port")]
    pub bmc_mock_port: u16,

    /// Set this to true if all BMC-mocks should be behind a single address (using HTTP headers to
    /// proxy to the real mock). This is the case for machine-a-tron running inside kubernetes
    /// clusters where there is a single k8s Service and we can't dynamically assign IP's.
    #[serde(default = "default_false")]
    pub use_single_bmc_mock: bool,

    #[serde(default = "default_bmc_mock_host_tar")]
    pub bmc_mock_host_tar: PathBuf,
    #[serde(default = "default_bmc_mock_dpu_tar")]
    pub bmc_mock_dpu_tar: PathBuf,
    #[serde(default = "default_false")]
    pub use_pxe_api: bool,
    pub pxe_server_host: Option<String>,
    pub pxe_server_port: Option<String>,
    pub sudo_command: Option<String>,
}

fn default_bmc_mock_port() -> u16 {
    2000
}
fn default_bmc_mock_host_tar() -> PathBuf {
    PathBuf::from("dev/bmc-mock/dell_poweredge_r750.tar.gz")
}
fn default_bmc_mock_dpu_tar() -> PathBuf {
    PathBuf::from("dev/bmc-mock/nvidia_dpu.tar.gz")
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

#[derive(Debug, Clone)]
pub struct MachineATronContext {
    pub app_config: MachineATronConfig,
    pub forge_client_config: ForgeClientConfig,
    pub circuit_id: Option<String>,
    pub bmc_mock_certs_dir: Option<PathBuf>,
    pub host_tar_router: Router,
    pub dpu_tar_router: Router,
}

fn as_std_duration<S>(d: &std::time::Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", d.as_secs()))
}
