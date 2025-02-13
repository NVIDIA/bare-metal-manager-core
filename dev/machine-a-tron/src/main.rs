use bmc_mock::{BmcMockHandle, ListenerOrAddress, TarGzOption};
use clap::Parser;
use figment::providers::{Format, Toml};
use figment::Figment;
use forge_tls::client_config::{
    get_client_cert_info, get_config_from_file, get_forge_root_ca_path, get_proxy_info,
};
use machine_a_tron::{
    api_client::ApiClient, api_throttler, DhcpRelayService, MachineATronArgs, MachineATronConfig,
    MachineATronContext, Tui, TuiHostLogs, UiEvent,
};
use machine_a_tron::{BmcMockRegistry, BmcRegistrationMode, MachineATron};
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, registry};

fn init_log(
    filename: &Option<String>,
    tui_host_logs: Option<&TuiHostLogs>,
) -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("hickory_proto=warn".parse().unwrap())
        .add_directive("hickory_resolver=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    match filename {
        Some(filename) => {
            let log_file = std::sync::Arc::new(std::fs::File::create(filename)?);
            registry()
                .with(fmt::Layer::default().compact().with_writer(log_file))
                .with(env_filter)
                .with(tui_host_logs.map(|l| l.make_tracing_layer()))
                .try_init()?;
        }
        None => registry()
            .with(fmt::Layer::default().compact().with_writer(std::io::stdout))
            .with(env_filter)
            .with(tui_host_logs.map(|l| l.make_tracing_layer()))
            .try_init()?,
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = MachineATronArgs::parse();

    let fig = Figment::new().merge(Toml::file(args.config_file.as_str()));
    let app_config: MachineATronConfig = fig.extract()?;
    let tui_host_logs = if app_config.tui_enabled {
        Some(TuiHostLogs::start_new(100))
    } else {
        None
    };

    init_log(&app_config.log_file, tui_host_logs.as_ref())?;

    let file_config = get_config_from_file();

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

    let dpu_tar_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_dpu_tar), None)?;
    let mut host_redfish_decompressed = HashMap::new();
    let host_tar_router = bmc_mock::tar_router(
        TarGzOption::Disk(&app_config.bmc_mock_host_tar),
        Some(&mut host_redfish_decompressed),
    )?;
    let host_redfish_routes = host_redfish_decompressed
        .into_values()
        .next()
        .expect("router creation should cache routes");

    let bmc_registration_mode = if app_config.use_single_bmc_mock {
        // Machines will register their BMC's with the shared registry
        BmcRegistrationMode::BackingInstance(BmcMockRegistry::default())
    } else {
        // Machines will each listen on a real BMC mock address using the configured port
        BmcRegistrationMode::None(app_config.bmc_mock_port)
    };

    let api_throttler = api_throttler::run(
        tokio::time::interval(Duration::from_secs(2)),
        app_config.carbide_api_url.clone(),
        forge_client_config.clone(),
    );

    let desired_firmware = ApiClient::from(ApiConfig::new(
        &app_config.carbide_api_url,
        &forge_client_config,
    ))
    .get_desired_firmware()
    .await?;

    tracing::info!(
        "Got desired firmware versions from the server: {:?}",
        desired_firmware
    );

    let bmc_mock_port = app_config.bmc_mock_port;
    let tui_enabled = app_config.tui_enabled;
    let app_context = Arc::new(MachineATronContext {
        app_config,
        forge_client_config,
        bmc_mock_certs_dir: None,
        host_tar_router,
        dpu_tar_router,
        bmc_registration_mode,
        api_throttler,
        desired_firmware_versions: desired_firmware,
    });

    let (mut dhcp_client, mut dhcp_service) = DhcpRelayService::new(app_context.clone());
    let dhcp_handle = tokio::spawn(async move {
        _ = dhcp_service
            .run()
            .await
            .inspect_err(|e| tracing::error!("Error running DHCP service: {}", e));
    });

    let info = app_context.api_client().version().await?;
    tracing::info!("version: {}", info.build_version);

    let mut mat = MachineATron::new(app_context.clone());

    // If we're using a combined BMC mock that routes to each mock machine using headers, launch it now
    let maybe_bmc_mock_handle: Option<BmcMockHandle> = match &app_context.bmc_registration_mode {
        BmcRegistrationMode::BackingInstance(bmc_mock_registry) => {
            let certs_dir = PathBuf::from(forge_root_ca_path.clone())
                .parent()
                .map(Path::to_path_buf);

            Some(
                bmc_mock::run_combined_mock(
                    bmc_mock_registry.clone(),
                    certs_dir,
                    Some(ListenerOrAddress::Address(
                        format!("0.0.0.0:{}", bmc_mock_port).parse().unwrap(),
                    )),
                )
                .await?,
            )
        }
        BmcRegistrationMode::None(_) => {
            // Otherwise each mock machine runs its own listener
            None
        }
    };

    let machine_actors = mat.make_machines(&dhcp_client, true).await?;

    // Run TUI
    let (app_tx, app_rx) = mpsc::channel(5000);
    let (tui_handle, tui_event_tx) = if tui_enabled {
        let (ui_tx, ui_rx) = mpsc::channel(5000);

        let host_redfish_routes = host_redfish_routes.clone();
        let tui_handle = Some(tokio::spawn(async {
            let mut tui = Tui::new(ui_rx, app_tx, host_redfish_routes, tui_host_logs);
            _ = tui.run().await.inspect_err(|e| {
                let estr = format!("Error running TUI: {e}");
                tracing::error!(estr);
                eprintln!("{}", estr); // dump it to stderr in case logs are getting redirected
            })
        }));
        (tui_handle, Some(ui_tx))
    } else {
        (None, None)
    };

    mat.run(machine_actors, tui_event_tx.clone(), app_rx)
        .await?;

    if let Some(tui_handle) = tui_handle {
        if let Some(ui_event_tx) = tui_event_tx.as_ref() {
            _ = ui_event_tx
                .try_send(UiEvent::Quit)
                .inspect_err(|e| tracing::warn!("Could not send quit signal to TUI: {e}"));
        }
        _ = tui_handle
            .await
            .inspect_err(|e| tracing::warn!("Error running TUI: {e}"));
    }

    dhcp_client.stop_service().await;
    dhcp_handle.await?;

    if let Some(mut bmc_mock_handle) = maybe_bmc_mock_handle {
        bmc_mock_handle.stop().await?;
    }

    Ok(())
}
