pub mod api_client;
pub mod bmc_mock_wrapper;
pub mod config;
pub mod dhcp_relay;
pub mod dpu_machine;
pub mod host_machine;
pub mod machine_a_tron;
pub mod machine_utils;
mod redfish_rewriter;
pub mod tui;

use std::error::Error;

use clap::Parser;
use figment::providers::{Format, Toml};
use figment::Figment;
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use machine_a_tron::MachineATron;
use rpc::forge_tls_client::ForgeClientConfig;

use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, registry};

use crate::config::{MachineATronArgs, MachineATronConfig, MachineATronContext};
use crate::dhcp_relay::DhcpRelayService;

fn init_log(filename: &Option<String>) -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    match filename {
        Some(filename) => {
            let log_file = std::sync::Arc::new(std::fs::File::create(filename)?);
            registry()
                .with(fmt::Layer::default().compact().with_writer(log_file))
                .with(env_filter)
                .try_init()?;
        }
        None => registry()
            .with(fmt::Layer::default().compact().with_writer(std::io::stdout))
            .with(env_filter)
            .try_init()?,
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = MachineATronArgs::parse();

    let fig = Figment::new().merge(Toml::file(args.config_file.as_str()));
    let mut app_config: MachineATronConfig = fig.extract()?;
    init_log(&app_config.log_file)?;

    let file_config = get_config_from_file();
    let carbide_api_url =
        get_carbide_api_url(app_config.carbide_api_url.clone(), file_config.as_ref());
    app_config.carbide_api_url = Some(carbide_api_url);

    let forge_root_ca_path = get_forge_root_ca_path(args.forge_root_ca_path, file_config.as_ref());
    let forge_client_cert = get_client_cert_info(
        args.client_cert_path,
        args.client_key_path,
        file_config.as_ref(),
    );
    let proxy =
        get_proxy_info().inspect_err(|e| tracing::error!("Failed to get proxy info: {}", e))?;

    let mut forge_client_config =
        ForgeClientConfig::new(forge_root_ca_path.clone(), Some(forge_client_cert));
    forge_client_config.socks_proxy(proxy);

    let mut app_context = MachineATronContext {
        app_config,
        forge_client_config,
        circuit_id: None,
    };

    let (mut dhcp_client, mut dhcp_service) =
        DhcpRelayService::new(app_context.clone(), app_context.app_config.clone());
    let dhcp_handle = tokio::spawn(async move {
        _ = dhcp_service
            .run()
            .await
            .inspect_err(|e| tracing::error!("Error running DHCP service: {}", e));
    });

    let segments = api_client::find_network_segments(&app_context).await?;

    for s in segments.network_segments.iter() {
        tracing::info!("segment: {:?}", s);
    }

    let circuit_id = segments
        .network_segments
        .iter()
        .find_map(|s| s.prefixes.iter().find_map(|p| p.circuit_id.clone()));
    app_context.circuit_id = circuit_id;

    let info = api_client::version(&app_context).await?;
    tracing::info!("version: {}", info.build_version);

    let mut mat = MachineATron::new(app_context);
    mat.run(&mut dhcp_client).await?;

    dhcp_client.stop_service().await;
    dhcp_handle.await?;
    Ok(())
}
