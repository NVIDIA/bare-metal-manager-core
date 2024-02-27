use std::time::Duration;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientConfig};
use tracing::{error, info, trace};

use crate::containerd::container;
use crate::containerd::container::ContainerSummary;

#[derive(Debug, Clone)]
pub struct MachineInventoryUpdaterConfig {
    /// How often to update the inventory
    pub update_inventory_interval: Duration,
    pub machine_id: String,
    pub forge_api: String,
    pub forge_client_config: ForgeClientConfig,
}

pub async fn single_run(config: &MachineInventoryUpdaterConfig) -> eyre::Result<()> {
    trace!(
        "Updating machine inventory for machine: {}",
        config.machine_id
    );

    let containers = container::Containers::list().await?;

    let images = container::Images::list().await?;

    trace!("Containers: {:?}", containers);

    let machine_id = config.machine_id.clone();

    let mut result: Vec<ContainerSummary> = Vec::new();

    // Map container images to container names
    for mut c in containers.containers {
        let images_clone = images.clone();
        let images_names = images_clone.find_by_id(&c.image.id)?;
        c.image_ref = images_names.names;
        result.push(c);
    }

    let inventory: Vec<rpc::MachineInventorySoftwareComponent> = result
        .into_iter()
        .flat_map(|c| {
            c.image_ref
                .into_iter()
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
        config.forge_client_config.clone(),
        &config.forge_api,
    )
    .await
    {
        error!(
            "Error while executing update_agent_reported_inventory: {:#}",
            e
        );
    } else {
        info!("Successfully updated machine inventory");
    }

    Ok(())
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

    trace!("update_machine_inventory: {:?}", inventory_report);

    let request = tonic::Request::new(inventory_report);
    match client.update_agent_reported_inventory(request).await {
        Ok(response) => {
            trace!("update_agent_reported_inventory response: {:?}", response);
            Ok(())
        }
        Err(err) => Err(eyre::eyre!(
            "Error while executing the update_agent_reported_inventory gRPC call: {}",
            err.to_string()
        )),
    }
}
