use bmc_mock::{BmcMockHandle, ListenerOrAddress, TarGzOption};
use clap::Parser;
use figment::providers::{Format, Toml};
use figment::Figment;
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use machine_a_tron::{
    api_client, DhcpRelayService, MachineATronArgs, MachineATronConfig, MachineATronContext, Tui,
    UiEvent,
};
use machine_a_tron::{BmcMockRegistry, BmcRegistrationMode, MachineATron};
use rpc::forge_tls_client::ForgeClientConfig;
use std::error::Error;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, registry};

fn init_log(filename: &Option<String>) -> Result<(), Box<dyn Error>> {
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

    let dpu_bmc_mock_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_dpu_tar), None)?;
    let host_bmc_mock_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_host_tar), None)?;

    let bmc_mock_port = app_config.bmc_mock_port;
    let use_single_bmc_mock = app_config.use_single_bmc_mock;
    let tui_enabled = app_config.tui_enabled;

    let mut app_context = MachineATronContext {
        app_config: app_config.clone(),
        forge_client_config,
        circuit_id: None,
        bmc_mock_certs_dir: None,
        dpu_tar_router: dpu_bmc_mock_router,
        host_tar_router: host_bmc_mock_router,
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

    let maybe_bmc_mock_handle: Option<BmcMockHandle>;
    let machine_actors = if use_single_bmc_mock {
        // Launch a single combined instance of BMC mock, with a shared registry that keeps track
        // of the individual "backing" mocks.
        let instance_registry = BmcMockRegistry::default();
        let certs_dir = PathBuf::from(forge_root_ca_path.clone())
            .parent()
            .map(Path::to_path_buf);

        // Run the combined mock
        maybe_bmc_mock_handle = Some(
            bmc_mock::run_combined_mock(
                instance_registry.clone(),
                certs_dir,
                Some(ListenerOrAddress::Address(
                    format!("0.0.0.0:{bmc_mock_port}").parse().unwrap(),
                )),
            )
            .await?,
        );

        // Construct machines, configuring them to register their BMC's with the shared registry
        mat.make_machines(
            &dhcp_client,
            BmcRegistrationMode::BackingInstance(instance_registry),
            true,
        )
        .await?
    } else {
        // Configure individual BMC mocks for every machine
        maybe_bmc_mock_handle = None;
        mat.make_machines(&dhcp_client, BmcRegistrationMode::None(bmc_mock_port), true)
            .await?
    };

    // Run TUI
    let (app_tx, app_rx) = mpsc::channel(5000);
    let (tui_handle, tui_event_tx) = if tui_enabled {
        let (ui_tx, ui_rx) = mpsc::channel(5000);

        let tui_handle = Some(tokio::spawn(async {
            let mut tui = Tui::new(ui_rx, app_tx);
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
