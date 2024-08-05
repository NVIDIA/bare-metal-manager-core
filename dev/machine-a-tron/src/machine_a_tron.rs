use std::collections::HashSet;

use crate::{
    api_client,
    config::MachineATronContext,
    dhcp_relay::DhcpRelayClient,
    host_machine::HostMachine,
    machine_utils::get_next_free_machine,
    tui::{Tui, UiEvent},
};

use crate::machine_state_machine::BmcRegistrationMode;
use crate::subnet::Subnet;
use crate::vpc::Vpc;
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(PartialEq, Eq)]
pub enum AppEvent {
    Quit,
    AllocateInstance,
}

pub struct MachineATron {
    app_context: MachineATronContext,
}

pub struct MachineHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: JoinHandle<()>,
}

impl MachineATron {
    pub fn new(app_context: MachineATronContext) -> Self {
        Self { app_context }
    }

    pub async fn make_machines(
        &self,
        dhcp_client: &DhcpRelayClient,
        bmc_listen_mode: BmcRegistrationMode,
    ) -> eyre::Result<Vec<HostMachine>> {
        let machines = self
            .app_context
            .app_config
            .machines
            .iter()
            .flat_map(|(config_name, config)| {
                tracing::info!("Constructing machines for config {}", config_name);
                (0..config.host_count).map(|_| {
                    HostMachine::new(
                        self.app_context.clone(),
                        config.clone(),
                        dhcp_client.clone(),
                        bmc_listen_mode.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();

        // Useful for comparing values in logs with machine-a-tron's state
        tracing::info!(
            "Machine-a-tron using machines: {:?}",
            machines
                .iter()
                .map(|m| m.host_machine_info().clone())
                .collect::<Vec<_>>()
        );

        Ok(machines)
    }

    pub async fn run(&mut self, machines: Vec<HostMachine>) -> eyre::Result<()> {
        let (app_tx, mut app_rx) = channel(5000);
        let mut machine_ids_or_mac_add: Vec<String> = Vec::new();
        let mut assigned_machine_ids: HashSet<String> = HashSet::new();
        let mut vpc_handles: Vec<Vpc> = Vec::new();
        let mut subnet_handles: Vec<Subnet> = Vec::new();

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
                let vpc = Vpc::new(app_context, config.clone(), ui_event_tx.clone()).await;

                for _ in 0..config.subnets_per_vpc {
                    let app_context = self.app_context.clone();

                    match Subnet::new(
                        app_context,
                        config.clone(),
                        ui_event_tx.clone(),
                        &vpc.vpc_name,
                    )
                    .await
                    {
                        Ok(subnet) => {
                            subnet_handles.push(subnet);
                        }
                        Err(e) => {
                            tracing::error!("Error creating network segment: {}", e);
                        }
                    }
                }
                vpc_handles.push(vpc);
            }
        }

        let mut machine_handles = Vec::default();
        for machine in machines {
            machine_ids_or_mac_add.push(machine.machine_id_with_fallback());
            let (stop_tx, stop_rx) = oneshot::channel();

            let join_handle = machine.start(stop_rx, ui_event_tx.clone(), false);

            machine_handles.push(MachineHandle {
                join_handle,
                stop_tx: Some(stop_tx),
            })
        }
        tracing::info!("Machine construction complete");

        while let Some(msg) = app_rx.recv().await {
            match msg {
                AppEvent::Quit => {
                    tracing::info!("quit");
                    for handle in machine_handles.iter_mut() {
                        if let Some(stop_tx) = handle.stop_tx.take() {
                            _ = stop_tx.send(());
                        }
                    }
                    break;
                }

                AppEvent::AllocateInstance => {
                    let machine_ids: Vec<_> =
                        api_client::find_machine_ids(&self.app_context.clone())
                            .await
                            .unwrap()
                            .machine_ids
                            .into_iter()
                            .map(|id| id.to_string())
                            .collect();

                    tracing::info!("Allocating an instance.");

                    let hid_for_instance = get_next_free_machine(
                        &self.app_context,
                        &machine_ids,
                        &assigned_machine_ids,
                    )
                    .await;
                    if hid_for_instance.is_empty() {
                        tracing::error!("No available machines.");
                        continue;
                    }

                    // TODO: Remove the hardcoded subnet_0 to be user specified through CLI.
                    match api_client::allocate_instance(
                        &self.app_context.clone(),
                        &hid_for_instance,
                        &"subnet_0".to_string(),
                    )
                    .await
                    {
                        Ok(_) => {
                            assigned_machine_ids.insert(hid_for_instance.clone());
                            tracing::info!("allocate_instance was successful. ");
                        }
                        Err(e) => {
                            tracing::info!("allocate_instance failed with {} ", e);
                        }
                    };
                }
            }
        }

        for machine_id in machine_ids_or_mac_add {
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

        for m in machine_handles.into_iter().map(|m| m.join_handle) {
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

        for subnet in subnet_handles {
            tracing::info!(
                "Attempting to delete network segment with id: {} from db.",
                subnet.segment_id
            );
            if let Err(e) =
                api_client::delete_network_segment(&self.app_context.clone(), &subnet.segment_id)
                    .await
            {
                tracing::error!("Delete network segment Api call failed with {}", e)
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
