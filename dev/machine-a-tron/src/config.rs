use std::{collections::BTreeMap, net::Ipv4Addr};

use clap::Parser;

use rpc::forge_tls_client::ForgeClientConfig;
use serde::{Deserialize, Serialize};

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

    #[clap(help = "Machine-A-Tron config file")]
    pub config_file: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineConfig {
    pub host_count: u32,
    pub dpu_per_host_count: u32,
    pub boot_delay: u32,
    pub template_dir: String,
    pub oob_dhcp_relay_address: Ipv4Addr,
    pub admin_dhcp_relay_address: Ipv4Addr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MachineATronConfig {
    // note that order is important in machines so that mac addresses are assigned the same way between runs
    pub machines: BTreeMap<String, MachineConfig>,
    pub carbide_api_url: Option<String>,
    pub log_file: Option<String>,
    pub interface: String,
    pub tui_enabled: bool,

    pub use_dhcp_api: bool,
    pub dhcp_server_address: String,

    #[serde(default = "default_bmc_mock_listen_address")]
    pub bmc_mock_listen_address: String,
    #[serde(default = "default_bmc_mock_host_tar")]
    pub bmc_mock_host_tar: String,
    #[serde(default = "default_bmc_mock_dpu_tar")]
    pub bmc_mock_dpu_tar: String,
}

fn default_bmc_mock_listen_address() -> String {
    String::from("0.0.0.0:2000")
}
fn default_bmc_mock_host_tar() -> String {
    String::from("dev/bmc-mock/lenovo_thinksystem_sr670.tar.gz")
}
fn default_bmc_mock_dpu_tar() -> String {
    String::from("dev/bmc-mock/nvidia_dpu.tar.gz")
}

#[derive(Debug, Clone)]
pub struct MachineATronContext {
    pub app_config: MachineATronConfig,
    pub forge_client_config: ForgeClientConfig,
    pub circuit_id: Option<String>,
}
