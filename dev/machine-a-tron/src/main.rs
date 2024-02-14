pub mod api_client;
pub mod machine;

use clap::Parser;
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use rpc::forge_tls_client::ForgeClientConfig;

use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, registry};

use crate::machine::HostMachine;

#[derive(Parser, Debug)]
#[clap(name = "machine-sim")]
pub struct MachineSimArgs {
    #[clap(help = "The number of host machines to create")]
    num_hosts: u32,
    // #[clap(help = "The number of DPUs per host to create")]
    // num_dpus_per_host: u32,
    #[clap(help = "the api url")]
    pub carbide_api: Option<String>,
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
    #[clap(long)]
    #[clap(help = "directory containing template files.")]
    pub template_dir: Option<String>,
    #[clap(long)]
    #[clap(help = "relay address for env.")]
    pub relay_address: String,
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    carbide_api_url: String,
    forge_client_config: ForgeClientConfig,
    pub template_dir: String,
    pub relay_address: String,
    pub num_hosts: u32,
    pub num_dpus_per_host: u32,
    pub circuit_id: Option<String>,
}

#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    registry()
        .with(fmt::Layer::default().compact().with_writer(std::io::stderr))
        .with(env_filter)
        .try_init()
        .unwrap();

    let args = MachineSimArgs::parse();

    let file_config = get_config_from_file();
    let carbide_api_url = get_carbide_api_url(args.carbide_api, file_config.as_ref());
    let forge_root_ca_path = get_forge_root_ca_path(args.forge_root_ca_path, file_config.as_ref());
    let forge_client_cert = get_client_cert_info(
        args.client_cert_path,
        args.client_key_path,
        file_config.as_ref(),
    );
    let proxy = get_proxy_info().expect("Failed to get proxy info");

    let mut forge_client_config =
        ForgeClientConfig::new(forge_root_ca_path, Some(forge_client_cert));
    forge_client_config.socks_proxy(proxy);

    let mut app_config = AppConfig {
        carbide_api_url,
        forge_client_config,
        template_dir: args.template_dir.unwrap_or("templates".to_owned()),
        relay_address: args.relay_address,
        num_hosts: args.num_hosts,
        num_dpus_per_host: 1, //args.num_dpus_per_host,
        circuit_id: None,
    };

    let segments = api_client::find_network_segments(&app_config)
        .await
        .unwrap();
    let circuit_id = segments
        .network_segments
        .iter()
        .find_map(|s| s.prefixes.iter().find_map(|p| p.circuit_id.clone()));

    app_config.circuit_id = circuit_id;

    let mut machines = Vec::default();
    for _ in 0..app_config.num_hosts {
        let m = HostMachine::new(app_config.clone());
        machines.push(m);
    }

    let info = api_client::version(&app_config).await.unwrap();
    tracing::info!("version: {}", info.build_version);

    loop {
        let mut work_done = false;
        for m in machines.iter_mut() {
            work_done |= m.process_state().await;
        }
        if !work_done {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}
