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
use std::borrow::Cow;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bmc_mock::{BmcMockHandle, HostnameQuerying, ListenerOrAddress};
use clap::Parser;
use figment::Figment;
use figment::providers::{Format, Toml};
use forge_tls::client_config::{
    get_client_cert_info, get_config_from_file, get_forge_root_ca_path, get_proxy_info,
};
use machine_a_tron::{
    AppEvent, BmcMockRegistry, BmcRegistrationMode, MachineATron, MachineATronArgs,
    MachineATronConfig, MachineATronContext, MockSshServerHandle, PromptBehavior, Tui, TuiHostLogs,
    api_throttler, spawn_mock_ssh_server,
};
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use rpc::protos::forge_api_client::ForgeApiClient;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry};

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

#[tokio::main(flavor = "multi_thread", worker_threads = 32)]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = MachineATronArgs::parse();
    let config_path = Path::new(&args.config_file);
    if !config_path.is_file() {
        Err(format!("config: {} is not file", args.config_file.as_str()))?;
    }
    let fig = Figment::new().merge(Toml::file(config_path));
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

    let bmc_registration_mode = if app_config.use_single_bmc_mock {
        // Machines will register their BMC's with the shared registry
        BmcRegistrationMode::BackingInstance(BmcMockRegistry::default())
    } else {
        // Machines will each listen on a real BMC mock address using the configured port
        BmcRegistrationMode::None(app_config.bmc_mock_port)
    };

    let api_config = ApiConfig::new(&app_config.carbide_api_url, &forge_client_config);

    let forge_api_client = ForgeApiClient::new(&api_config);

    let api_throttler = api_throttler::run(
        tokio::time::interval(Duration::from_secs(2)),
        forge_api_client.clone().into(),
    );

    let desired_firmware_versions = forge_api_client
        .get_desired_firmware_versions()
        .await?
        .entries;

    tracing::info!(
        "Got desired firmware versions from the server: {:?}",
        desired_firmware_versions
    );

    let bmc_mock_port = app_config.bmc_mock_port;
    let tui_enabled = app_config.tui_enabled;

    let app_context = Arc::new(MachineATronContext {
        app_config,
        forge_client_config,
        bmc_mock_certs_dir: None,
        bmc_registration_mode,
        api_throttler,
        desired_firmware_versions,
        forge_api_client,
    });

    let info = app_context.forge_api_client.version(false).await?;
    tracing::info!("version: {}", info.build_version);

    let mut mat = MachineATron::new(app_context.clone());

    // If we're using a combined BMC mock that routes to each mock machine using headers, launch it now
    let maybe_bmc_mock_handles: Option<(BmcMockHandle, Option<MockSshServerHandle>)> =
        match &app_context.bmc_registration_mode {
            BmcRegistrationMode::BackingInstance(bmc_mock_registry) => {
                let certs_dir = PathBuf::from(forge_root_ca_path.clone())
                    .parent()
                    .map(Path::to_path_buf);

                let bmc_https_mock = bmc_mock::run_combined_mock(
                    bmc_mock_registry.clone(),
                    certs_dir,
                    Some(ListenerOrAddress::Address(
                        format!("0.0.0.0:{bmc_mock_port}").parse().unwrap(),
                    )),
                )?;

                let bmc_ssh_mock = if app_context.app_config.mock_bmc_ssh_server {
                    // Spawn a single mock SSH server too. ssh-console can be configured to talk to
                    // this instead of the carbide-assigned BMC IP for each host, so that
                    // machine-a-tron-based dev environments can have a "working" ssh-console too.
                    Some(
                        spawn_mock_ssh_server(
                            "0.0.0.0".parse().unwrap(),
                            app_context.app_config.mock_bmc_ssh_port,
                            Arc::new(KnownHostname("shared-bmc-mock".to_string())),
                            // Accept any credentials. We don't support mocking changing BMC
                            // credentials, so we can't properly emulate BMC SSH credentials in dev
                            // environments today. (Only ssh-console integration tests use
                            // credentials here as of today.)
                            None,
                            PromptBehavior::Dell,
                        )
                        .await?,
                    )
                } else {
                    None
                };

                Some((bmc_https_mock, bmc_ssh_mock))
            }
            BmcRegistrationMode::None(_) => {
                // Otherwise each mock machine runs its own listener
                None
            }
        };

    let machine_handles = mat.make_machines(true).await?;

    // Persist them once in case of unclean shutdown
    app_context.app_config.write_persisted_machines(
        machine_handles
            .iter()
            .map(|m| m.persisted())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;

    // Run TUI
    let (app_tx, app_rx) = mpsc::channel(5000);
    let (tui_handle, tui_event_tx, tui_quit_tx) = if tui_enabled {
        let (ui_tx, ui_rx) = mpsc::channel(5000);
        let (quit_tx, quit_rx) = mpsc::channel(1);

        let host_redfish_routes = Default::default();
        let tui_handle = Some(tokio::spawn(async {
            let mut tui = Tui::new(ui_rx, quit_rx, app_tx, host_redfish_routes, tui_host_logs);
            _ = tui.run().await.inspect_err(|e| {
                let estr = format!("Error running TUI: {e}");
                tracing::error!(estr);
                eprintln!("{estr}"); // dump it to stderr in case logs are getting redirected
            })
        }));
        (tui_handle, Some(ui_tx), Some(quit_tx))
    } else {
        // Create a signal stream for SIGTERM and SIGINT.
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to create SIGTERM signal stream");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to create SIGINT signal stream");

        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
            app_tx.send(AppEvent::Quit).await.ok();
        });

        (None, None, None)
    };

    mat.run(machine_handles, tui_event_tx.clone(), app_rx)
        .await?;

    if let Some(tui_handle) = tui_handle {
        if let Some(tui_quit_tx) = tui_quit_tx.as_ref() {
            _ = tui_quit_tx
                .try_send(())
                .inspect_err(|e| tracing::warn!("Could not send quit signal to TUI: {e}"));
        }
        tui_handle
            .await
            .inspect_err(|e| tracing::warn!("Error running TUI: {e}"))
            .ok();
    }

    if let Some((mut bmc_mock_handle, _mock_ssh_server_handle)) = maybe_bmc_mock_handles {
        bmc_mock_handle.stop().await?;
    }
    Ok(())
}

#[derive(Debug)]
struct KnownHostname(String);

impl HostnameQuerying for KnownHostname {
    fn get_hostname(&'_ self) -> Cow<'_, str> {
        Cow::Borrowed(self.0.as_str())
    }
}
