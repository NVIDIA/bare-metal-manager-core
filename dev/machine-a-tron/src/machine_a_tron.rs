use std::collections::HashSet;

use crate::host_machine::HostMachineActor;
use crate::machine_state_machine::BmcRegistrationMode;
use crate::subnet::Subnet;
use crate::vpc::Vpc;
use crate::{
    api_client, config::MachineATronContext, dhcp_relay::DhcpRelayClient,
    host_machine::HostMachine, machine_utils::get_next_free_machine, tui::UiEvent,
};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(PartialEq, Eq)]
pub enum AppEvent {
    Quit,
    AllocateInstance,
}

pub struct MachineATron {
    app_context: MachineATronContext,
}

impl MachineATron {
    pub fn new(app_context: MachineATronContext) -> Self {
        Self { app_context }
    }

    pub async fn make_machines(
        &self,
        dhcp_client: &DhcpRelayClient,
        bmc_listen_mode: BmcRegistrationMode,
        paused: bool,
    ) -> eyre::Result<Vec<HostMachineActor>> {
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
                    .start(paused)
                })
            })
            .collect::<Vec<_>>();

        // Useful for comparing values in logs with machine-a-tron's state
        tracing::info!(
            "Machine-a-tron using machines: {:?}",
            machines
                .iter()
                .map(|m| m.host_machine_info.clone())
                .collect::<Vec<_>>()
        );

        Ok(machines)
    }

    pub async fn run(
        &mut self,
        machine_actors: Vec<HostMachineActor>,
        tui_event_tx: Option<mpsc::Sender<UiEvent>>,
        mut app_rx: mpsc::Receiver<AppEvent>,
    ) -> eyre::Result<()> {
        let mut vpc_handles: Vec<Vpc> = Vec::new();
        let mut subnet_handles: Vec<Subnet> = Vec::new();
        // Represents the mat_id of machines which are Assigned to a forge Instance
        let mut assigned_mat_ids: HashSet<Uuid> = HashSet::new();

        for (_config_name, config) in self.app_context.app_config.machines.iter() {
            for _ in 0..config.vpc_count {
                let app_context = self.app_context.clone();
                let vpc = Vpc::new(app_context, config.clone(), tui_event_tx.clone()).await;

                for _ in 0..config.subnets_per_vpc {
                    let app_context = self.app_context.clone();

                    match Subnet::new(
                        app_context,
                        config.clone(),
                        tui_event_tx.clone(),
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

        for machine_actor in &machine_actors {
            machine_actor.attach_to_tui(tui_event_tx.clone())?;
            machine_actor.resume()?;
        }

        tracing::info!("Machine construction complete");

        while let Some(msg) = app_rx.recv().await {
            match msg {
                AppEvent::Quit => {
                    tracing::info!("quit");
                    for machine_actor in machine_actors.into_iter() {
                        machine_actor.stop(true).await?;
                    }
                    break;
                }

                AppEvent::AllocateInstance => {
                    tracing::info!("Allocating an instance.");

                    let Some(free_machine) =
                        get_next_free_machine(&machine_actors, &assigned_mat_ids).await
                    else {
                        tracing::error!("No available machines.");
                        continue;
                    };

                    let Some(hid_for_instance) = free_machine.observed_machine_id().await? else {
                        tracing::error!("Machine in state Ready but with no machine ID?");
                        continue;
                    };

                    // TODO: Remove the hardcoded subnet_0 to be user specified through CLI.
                    match api_client::allocate_instance(
                        &self.app_context.clone(),
                        &hid_for_instance.to_string(),
                        &"subnet_0".to_string(),
                    )
                    .await
                    {
                        Ok(_) => {
                            assigned_mat_ids.insert(free_machine.mat_id);
                            tracing::info!("allocate_instance was successful. ");
                        }
                        Err(e) => {
                            tracing::info!("allocate_instance failed with {} ", e);
                        }
                    };
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

        tracing::info!("machine-a-tron finished");
        Ok(())
    }
}
