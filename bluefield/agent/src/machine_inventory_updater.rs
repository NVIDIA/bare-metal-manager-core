use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::containerd::container;
use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientConfig};
use tracing::{error, info, trace};

struct MachineInventoryUpdaterState {
    config: MachineInventoryUpdaterConfig,
    is_cancelled: AtomicBool,
}

pub struct MachineInventoryUpdater {
    state: Arc<MachineInventoryUpdaterState>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

pub struct MachineInventoryUpdaterConfig {
    /// How often to update the inventory
    pub update_inventory_interval: Duration,
    pub machine_id: String,
    pub forge_api: String,
    pub forge_client_config: ForgeClientConfig,
}

impl Drop for MachineInventoryUpdater {
    fn drop(&mut self) {
        // Signal the background task and wait for it to shut down
        // TODO: Might be nicer if it would be interrupted during waiting for 30s
        self.state
            .is_cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(jh) = self.join_handle.take() {
            tokio::spawn(async move {
                jh.await.unwrap();
            });
        }
    }
}

impl MachineInventoryUpdater {
    pub fn new(config: MachineInventoryUpdaterConfig) -> Self {
        let forge_client_config = config.forge_client_config.clone();
        let state = Arc::new(MachineInventoryUpdaterState {
            config,
            is_cancelled: AtomicBool::new(false),
        });

        let task_state = state.clone();
        let join_handle = tokio::spawn(async move {
            run_machine_inventory_updater(forge_client_config, task_state).await
        });

        Self {
            state,
            join_handle: Some(join_handle),
        }
    }
}

async fn run_machine_inventory_updater(
    forge_client_config: ForgeClientConfig,
    state: Arc<MachineInventoryUpdaterState>,
) {
    loop {
        if state
            .is_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            trace!("MachineInventoryUpdater was dropped, exiting loop");
            break;
        }
        trace!(
            "Updating machine inventory for machine: {}",
            state.config.machine_id
        );

        let containers = container::Containers::list().unwrap();
        trace!("Containers: {:?}", containers);

        let machine_id = state.config.machine_id.clone();

        let inventory: Vec<rpc::MachineInventorySoftwareComponent> = containers
            .containers
            .into_iter()
            .flat_map(|c| {
                c.image_ref
                    .names
                    .iter()
                    .map(|n| rpc::MachineInventorySoftwareComponent {
                        name: n.name.clone(),
                        version: n.version.clone(),
                        url: n.repository.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let inventory = rpc::MachineInventory {
            components: inventory,
        };

        let agent_report = rpc::DpuAgentInventoryReport {
            machine_id: Some(rpc::MachineId { id: machine_id }),
            inventory: Some(inventory),
        };

        if let Err(e) = update_agent_reported_inventory(
            agent_report,
            forge_client_config.clone(),
            &state.config.forge_api,
        )
        .await
        {
            error!(
                "Error while executing update_agent_reported_inventory: {:#}",
                e
            );
        }
        tokio::time::sleep(state.config.update_inventory_interval).await;
    }
}

async fn update_agent_reported_inventory(
    inventory_report: rpc::DpuAgentInventoryReport,
    forge_client_config: forge_tls_client::ForgeClientConfig,
    forge_api: &str,
) -> eyre::Result<()> {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            return Err(eyre::eyre!(
                "Could not connect to Forge API server at {}: {err}",
                forge_api
            ));
        }
    };

    info!("update_machine_inventory: {:?}", inventory_report);

    let request = tonic::Request::new(inventory_report);
    match client.update_agent_reported_inventory(request).await {
        Ok(response) => {
            trace!("update_agent_reported_inventory response: {:?}", response);
            Ok(())
        }
        Err(err) => Err(eyre::eyre!(
            "Error while executing the update_machine_inventory gRPC call: {}",
            err.to_string()
        )),
    }
}
