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
    BmcMockRegistry, BmcRegistrationMode, DhcpRelayService, MachineATron, MachineATronConfig,
    MachineATronContext,
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
) -> eyre::Result<MachineATronInstance> {
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

    let mat = MachineATron::new(app_context);
    let machines = mat
        .make_machines(
            &dhcp_client,
            BmcRegistrationMode::BackingInstance(bmc_address_registry.clone()),
        )
        .await?;

    let machine_jobs = machines
        .into_iter()
        .map(|machine| {
            let (_stop_tx, stop_rx) = oneshot::channel();
            let join_handle = machine.start(stop_rx, None, true);
            MachineJob {
                join_handle,
                _stop_tx,
            }
        })
        .collect::<Vec<_>>();

    let all_machines_job = tokio::spawn(async move {
        for machine_job in machine_jobs {
            machine_job.join_handle.await?
        }
        dhcp_client.stop_service().await;
        dhcp_handle.await?;
        Ok(())
    });

    Ok(MachineATronInstance {
        join_handle: all_machines_job,
    })
}

pub struct MachineATronInstance {
    pub join_handle: JoinHandle<eyre::Result<()>>,
}

struct MachineJob {
    join_handle: JoinHandle<()>,
    _stop_tx: oneshot::Sender<()>,
}
