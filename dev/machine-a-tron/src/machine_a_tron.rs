use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    config::MachineATronContext,
    dhcp_relay::DhcpRelayClient,
    host_machine::HostMachine,
    tui::{Tui, UiEvent},
};

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

    pub async fn run(&mut self, dhcp_client: &mut DhcpRelayClient) {
        let running = Arc::new(AtomicBool::new(true));
        let (app_tx, mut app_rx) = channel(5000);

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

        let mut machine_handles = Vec::default();

        for (config_name, config) in self.app_context.app_config.machines.iter() {
            tracing::info!("Constructing machines for config {}", config_name);
            for _ in 0..config.host_count {
                let running = running.clone();
                let app_context = self.app_context.clone();
                let mut dhcp_client_clone = dhcp_client.clone();
                let mut machine =
                    HostMachine::new(app_context, config.clone(), ui_event_tx.clone());

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

        for m in machine_handles {
            m.abort();
            if let Err(e) = m.await {
                if !e.is_cancelled() {
                    tracing::warn!("Failed to clean up machine task: {e}");
                }
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
    }
}
