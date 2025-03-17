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
use bmc_mock::TarGzOption;
use forge_tls::client_config::get_forge_root_ca_path;
use machine_a_tron::{
    BmcMockRegistry, BmcRegistrationMode, DhcpRelayService, HostMachineActor, MachineATron,
    MachineATronConfig, MachineATronContext, api_throttler,
};
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Run a machine-a-tron instance with the given config in the background, returning a JoinHandle
/// that can be waited on.
///
/// The background job will continually run [HostMachine::process_state] on each machine until each
/// of them reaches a `Ready` state, then it will return. Callers are responsible for configuring a
/// timeout in case a ready state is not reached.
pub async fn run_local(
    app_config: MachineATronConfig,
    repo_root: PathBuf,
    bmc_address_registry: BmcMockRegistry,
) -> eyre::Result<(Vec<HostMachineActor>, MachineATronHandle)> {
    let forge_root_ca_path = get_forge_root_ca_path(None, None); // Will get it from the local repo
    let forge_client_config = ForgeClientConfig::new(forge_root_ca_path.clone(), None);

    let dpu_tar_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_dpu_tar), None)?;
    let host_tar_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_host_tar), None)?;

    let forge_api_client = ForgeApiClient::new(&ApiConfig::new(
        &app_config.carbide_api_url,
        &forge_client_config,
    ));

    let api_throttler = api_throttler::run(
        tokio::time::interval(Duration::from_secs(2)),
        forge_api_client.clone().into(),
    );

    let desired_firmware = forge_api_client
        .get_desired_firmware_versions()
        .await?
        .entries;

    tracing::info!(
        "Got desired firmware versions from the server: {:?}",
        desired_firmware
    );

    let app_context = Arc::new(MachineATronContext {
        app_config,
        forge_client_config,
        bmc_mock_certs_dir: Some(repo_root.join("dev/bmc-mock")),
        host_tar_router,
        dpu_tar_router,
        bmc_registration_mode: BmcRegistrationMode::BackingInstance(bmc_address_registry.clone()),
        api_throttler,
        desired_firmware_versions: desired_firmware,
        forge_api_client,
    });

    // Start DHCP relay
    let (mut dhcp_client, mut dhcp_service) = DhcpRelayService::new(app_context.clone());
    let dhcp_handle = tokio::spawn(async move {
        _ = dhcp_service.run().await.inspect_err(|e| {
            eprintln!("Error running DHCP service: {}", e);
            tracing::error!("Error running DHCP service: {}", e);
        });
    });

    let mat = MachineATron::new(app_context.clone());
    let machine_actors = mat.make_machines(&dhcp_client, false).await?;

    let (stop_tx, stop_rx) = oneshot::channel();
    let machine_actors_clone = machine_actors.clone();
    let join_handle = tokio::spawn(async move {
        stop_rx.await?;

        for machine_actor in machine_actors_clone.into_iter() {
            machine_actor.stop(true).await?;
        }

        dhcp_client.stop_service().await;
        dhcp_handle.await?;
        Ok(())
    });

    Ok((
        machine_actors,
        MachineATronHandle {
            stop_tx,
            join_handle,
        },
    ))
}

pub struct MachineATronHandle {
    stop_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<eyre::Result<()>>,
}

impl MachineATronHandle {
    pub async fn stop(self) -> eyre::Result<()> {
        _ = self.stop_tx.send(());
        self.join_handle.await?
    }
}
