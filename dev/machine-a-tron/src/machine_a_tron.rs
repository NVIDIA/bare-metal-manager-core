use std::path::Path;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    api_client,
    config::MachineATronContext,
    dhcp_relay::DhcpRelayClient,
    host_machine::HostMachine,
    tui::{Tui, UiEvent},
};

use crate::vpc::Vpc;
use tokio::sync::mpsc::channel;

#[derive(PartialEq, Eq)]
pub enum AppEvent {
    Quit,
}

pub struct MachineATron {
    app_context: MachineATronContext,
}

impl MachineATron {
    pub fn new(app_context: MachineATronContext) -> Self {
        Self { app_context }
    }

    pub async fn run(&mut self, dhcp_client: &mut DhcpRelayClient) -> eyre::Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let (app_tx, mut app_rx) = channel(5000);
        let mut machine_ids: Vec<String> = Vec::new();
        let mut vpc_handles: Vec<Vpc> = Vec::new();

        let (tui_handle, ui_event_tx) = if self.app_context.app_config.tui_enabled {
            let (ui_tx, ui_rx) = channel(5000);

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

        for (_config_name, config) in self.app_context.app_config.machines.iter() {
            for _ in 0..config.vpc_count {
                let app_context = self.app_context.clone();
                let vpc = Vpc::new(app_context, config.clone(), ui_event_tx.clone());
                vpc_handles.push(vpc.await);
            }
        }

        let mut machine_handles = Vec::default();

        let dpu_bmc_mock_router = bmc_mock::tar_router(
            Path::new(self.app_context.app_config.bmc_mock_dpu_tar.as_str()),
            None,
        )?;
        let host_bmc_mock_router = bmc_mock::tar_router(
            Path::new(self.app_context.app_config.bmc_mock_host_tar.as_str()),
            None,
        )?;

        for (config_name, config) in self.app_context.app_config.machines.iter() {
            tracing::info!("Constructing machines for config {}", config_name);
            for _ in 0..config.host_count {
                let running = running.clone();
                let app_context = self.app_context.clone();
                let mut dhcp_client_clone = dhcp_client.clone();
                let mut machine = HostMachine::new(
                    app_context,
                    config.clone(),
                    ui_event_tx.clone(),
                    host_bmc_mock_router.clone(),
                    dpu_bmc_mock_router.clone(),
                );
                machine_ids.push(machine.get_machine_id_str());

                let join_handle = tokio::spawn(async move {
                    while running.as_ref().load(Ordering::Relaxed) {
                        let work_done = machine
                            .process_state(&mut dhcp_client_clone)
                            .await
                            .inspect_err(|e| tracing::error!("Error processing state: {e}"))
                            .unwrap_or(false);
                        if work_done {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        } else {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    }
                });
                machine_handles.push(join_handle);
            }
        }
        tracing::info!("Machine construction complete");

        while running.as_ref().load(Ordering::Relaxed)
            && !tui_handle.as_ref().is_some_and(|t| t.is_finished())
        {
            if let Some(msg) = app_rx.recv().await {
                if msg == AppEvent::Quit {
                    tracing::info!("quit");
                    running.store(false, Ordering::Relaxed);
                }
            }
        }

        for machine_id in machine_ids {
            tracing::info!(
                "Attempting to delete machine with id: {} from db.",
                machine_id
            );
            if let Err(e) =
                api_client::force_delete_machine(&self.app_context.clone(), machine_id).await
            {
                tracing::error!("Force delete Api call failed with {}", e)
            }
        }

        for m in machine_handles {
            m.abort();
            if let Err(e) = m.await {
                if !e.is_cancelled() {
                    tracing::warn!("Failed to clean up machine task: {e}");
                }
            }
        }

        // Following block does not remove the entries from the VPC table due to possible references by other places.
        // It rather soft deletes the VPCs by updating the deleted column of a vpc.
        for vpc in vpc_handles {
            tracing::info!("Attempting to delete VPC with id: {} from db.", vpc.vpc_id);
            if let Err(e) = api_client::delete_vpc(&self.app_context.clone(), &vpc.vpc_id).await {
                tracing::error!("Delete VPC Api call failed with {}", e)
            }
        }

        if let Some(tui_handle) = tui_handle {
            if let Some(ui_event_tx) = ui_event_tx.as_ref() {
                _ = ui_event_tx
                    .try_send(UiEvent::Quit)
                    .inspect_err(|e| tracing::warn!("Could not send quit signal to TUI: {e}"));
            }
            _ = tui_handle
                .await
                .inspect_err(|e| tracing::warn!("Error running TUI: {e}"));
        }

        tracing::info!("machine-a-tron finished");
        Ok(())
    }
}
