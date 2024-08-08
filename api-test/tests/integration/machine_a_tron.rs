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
use futures::future::join_all;
use machine_a_tron::api_client::allocate_instance;
use machine_a_tron::{
    BmcMockRegistry, BmcRegistrationMode, DhcpRelayService, HostMachineActor, MachineATron,
    MachineATronConfig, MachineATronContext,
};
use rpc::forge_tls_client::ForgeClientConfig;
use std::path::PathBuf;
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
) -> eyre::Result<MachineATronHandle> {
    let forge_root_ca_path = get_forge_root_ca_path(None, None); // Will get it from the local repo
    let forge_client_config = ForgeClientConfig::new(forge_root_ca_path.clone(), None);

    let dpu_tar_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_dpu_tar), None)?;
    let host_tar_router =
        bmc_mock::tar_router(TarGzOption::Disk(&app_config.bmc_mock_host_tar), None)?;

    let app_context = MachineATronContext {
        app_config,
        forge_client_config,
        circuit_id: None,
        bmc_mock_certs_dir: Some(repo_root.join("dev/bmc-mock")),
        dpu_tar_router,
        host_tar_router,
    };

    // Start DHCP relay
    let (mut dhcp_client, mut dhcp_service) =
        DhcpRelayService::new(app_context.clone(), app_context.app_config.clone());
    let dhcp_handle = tokio::spawn(async move {
        _ = dhcp_service.run().await.inspect_err(|e| {
            eprintln!("Error running DHCP service: {}", e);
            tracing::error!("Error running DHCP service: {}", e);
        });
    });

    let mat = MachineATron::new(app_context.clone());
    let machine_actors = mat
        .make_machines(
            &dhcp_client,
            BmcRegistrationMode::BackingInstance(bmc_address_registry.clone()),
            false,
        )
        .await?;

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let join_handle = tokio::spawn(async move {
        let all_result = join_all(machine_actors.iter().map(|machine_actor| {
            let app_context = app_context.clone();
            async move {
                machine_actor
                    .wait_until_machine_up_with_api_state("Ready")
                    .await?;
                let machine_id = machine_actor
                    .observed_machine_id()
                    .await?
                    .expect("Machine ID should be set if host is ready");
                tracing::info!("Machine {machine_id} has made it to Ready, allocating instance");
                allocate_instance(&app_context.clone(), &machine_id.to_string(), "tenant1").await?;
                machine_actor
                    .wait_until_machine_up_with_api_state("Assigned/Ready")
                    .await?;
                tracing::info!("Machine {machine_id} has made it to Assigned/Ready, all done");
                Ok::<HostMachineActor, eyre::Report>(machine_actor.clone())
            }
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, eyre::Report>>();

        _ = ready_tx.send(all_result);
        stop_rx.await?;

        for machine_actor in machine_actors.into_iter() {
            machine_actor.stop(true).await?;
        }

        dhcp_client.stop_service().await;
        dhcp_handle.await?;
        Ok(())
    });

    Ok(MachineATronHandle {
        ready_rx: Some(ready_rx),
        stop_tx_and_join_handle: Some((stop_tx, join_handle)),
    })
}

pub struct MachineATronHandle {
    ready_rx: Option<oneshot::Receiver<eyre::Result<Vec<HostMachineActor>>>>,
    stop_tx_and_join_handle: Option<(oneshot::Sender<()>, JoinHandle<eyre::Result<()>>)>,
}

impl MachineATronHandle {
    pub async fn wait_until_ready(&mut self) -> eyre::Result<Vec<HostMachineActor>> {
        if let Some(ready_rx) = self.ready_rx.take() {
            ready_rx.await?
        } else {
            Err(eyre::Report::msg("Ready channel already awaited"))
        }
    }

    pub async fn stop(&mut self) -> eyre::Result<()> {
        if let Some((stop_tx, join_handle)) = self.stop_tx_and_join_handle.take() {
            _ = stop_tx.send(());
            join_handle.await?
        } else {
            Err(eyre::Report::msg("Stop channel already consumed"))
        }
    }
}
