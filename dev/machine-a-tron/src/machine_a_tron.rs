use std::{collections::HashMap, time::Duration};

use crate::{
    config::MachineATronContext,
    dhcp_relay::DhcpRelayClient,
    host_machine::HostMachine,
    tui::{Tui, UiEvent},
};

use tokio::{
    select,
    sync::mpsc::{channel, Sender},
};
use uuid::Uuid;

#[derive(PartialEq, Eq)]
pub enum AppEvent {
    Quit,
}

pub struct MachineATron {
    app_context: MachineATronContext,
    dhcp_client: DhcpRelayClient,
    machines: HashMap<Uuid, HostMachine>,
    mat_id_index: HashMap<Uuid, Uuid>,
}

impl MachineATron {
    pub fn new(app_context: MachineATronContext, dhcp_client: DhcpRelayClient) -> Self {
        let mut machines = HashMap::default();
        let mut mat_id_index = HashMap::default();

        for (config_name, config) in app_context.app_config.machines.iter() {
            tracing::info!("Constructing machines for config {}", config_name);
            for _ in 0..config.host_count {
                let m = HostMachine::new(app_context.clone(), config.clone());
                mat_id_index.insert(m.mat_id, m.mat_id);
                mat_id_index.insert(m.bmc_mat_id, m.mat_id);
                for d in m.dpu_machines.iter() {
                    mat_id_index.insert(d.mat_id, m.mat_id);
                    mat_id_index.insert(d.bmc_mat_id, m.mat_id);
                }
                machines.insert(m.mat_id, m);
            }
        }
        Self {
            app_context,
            dhcp_client,
            machines,
            mat_id_index,
        }
    }

    async fn process_machines(&mut self, ui_tx: &mut Sender<UiEvent>) {
        for (_id, machine) in self.machines.iter_mut() {
            let machine_changed = machine.process_state(&mut self.dhcp_client).await;
            if machine_changed && self.app_context.app_config.tui_enabled {
                ui_tx
                    .send(UiEvent::MachineUpdate(machine.clone()))
                    .await
                    .unwrap();
            }
        }
    }

    pub async fn run(&mut self) {
        let mut running = true;
        let (mut ui_tx, ui_rx) = channel(5000);
        let (app_tx, mut app_rx) = channel(5000);

        let tui_handle = if self.app_context.app_config.tui_enabled {
            let tui_handle = Some(tokio::spawn(async {
                let mut tui = Tui::new(ui_rx, app_tx);
                tui.run().await;
            }));
            for (_id, m) in self.machines.iter() {
                ui_tx.send(UiEvent::MachineUpdate(m.clone())).await.unwrap();
            }
            tui_handle
        } else {
            None
        };

        let mut dhcp_client = self.dhcp_client.clone();

        while running && !tui_handle.as_ref().is_some_and(|t| t.is_finished()) {
            select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    self.process_machines(&mut ui_tx).await;
                 },
                msg = app_rx.recv() => {
                    if let Some(AppEvent::Quit) = msg {
                        tracing::info!("quit");
                        ui_tx.try_send(UiEvent::Quit).unwrap();
                        running = false;
                   }
                }
                dhcp_response_info = dhcp_client.receive_ip() => {
                    if let Some(mat_id) = self.mat_id_index.get(&dhcp_response_info.mat_id) {
                        if let Some(machine) = self.machines.get_mut(mat_id) {
                            machine.update_dhcp_info(dhcp_response_info);
                        } else {
                            tracing::warn!("No machin for {}", mat_id);
                        }
                    } else {
                        tracing::warn!("No index entry for {}", dhcp_response_info.mat_id);
                    }
                }
            }
        }

        if let Some(tui_handle) = tui_handle {
            tui_handle.await.unwrap();
        }
        tracing::info!("machine-a-tron finished");
    }
}
