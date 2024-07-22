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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use forge_tls::client_config::get_forge_root_ca_path;
use machine_a_tron::config::{MachineATronConfig, MachineATronContext};
use machine_a_tron::dhcp_relay::DhcpRelayService;
use machine_a_tron::host_machine::HostMachine;
use machine_a_tron::machine_a_tron::MachineATron;
use rpc::forge_tls_client::ForgeClientConfig;

/// Run a machine-a-tron instance with the given config in the background, returning a JoinHandle
/// that can be waited on.
///
/// The background job will continually run [HostMachine::process_state] on each machine until each
/// of them reaches a `Ready` state, then it will return. Callers are responsible for configuring a
/// timeout in case a ready state is not reached.
pub async fn run_local(
    app_config: MachineATronConfig,
    repo_root: PathBuf,
) -> eyre::Result<MachineATronInstance> {
    let forge_root_ca_path = get_forge_root_ca_path(None, None); // Will get it from the local repo
    let forge_client_config = ForgeClientConfig::new(forge_root_ca_path.clone(), None);

    let dpu_bmc_mock_router =
        bmc_mock::tar_router(Path::new(app_config.bmc_mock_dpu_tar.as_str()), None)?;
    let host_bmc_mock_router =
        bmc_mock::tar_router(Path::new(app_config.bmc_mock_host_tar.as_str()), None)?;

    let app_context = MachineATronContext {
        app_config,
        forge_client_config,
        circuit_id: None,
        bmc_mock_certs_dir: Some(repo_root.join("dev/bmc-mock")),
        dpu_bmc_mock_router,
        host_bmc_mock_router,
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
        .make_machines(&dhcp_client)
        .await?
        .into_iter()
        .map(|m| Arc::new(Mutex::new(m)))
        .collect::<Vec<_>>();

    let machine_jobs = machines
        .iter()
        .map(|machine| {
            let machine = machine.clone();

            tokio::spawn(async move {
                loop {
                    let mut machine = machine.lock().await;
                    let work_done = machine
                        .process_state()
                        .await
                        .inspect_err(|e| tracing::error!("Error processing state: {e}"))?;

                    if machine.is_up_and_ready() {
                        tracing::info!(
                            "Machine {} has made it to Ready/MachineUp, all done.",
                            machine.machine_id_with_fallback()
                        );
                        break;
                    }

                    if work_done {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                Ok::<_, eyre::Report>(())
            })
        })
        .collect::<Vec<_>>();

    let all_machines_job = tokio::spawn(async move {
        for machine_job in machine_jobs {
            machine_job.await??;
        }
        dhcp_client.stop_service().await;
        dhcp_handle.await?;
        Ok(())
    });

    Ok(MachineATronInstance {
        host_machines: machines,
        join_handle: all_machines_job,
    })
}

pub struct MachineATronInstance {
    pub host_machines: Vec<Arc<Mutex<HostMachine>>>,
    pub join_handle: JoinHandle<eyre::Result<()>>,
}
