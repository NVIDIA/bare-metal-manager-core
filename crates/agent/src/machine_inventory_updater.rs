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
use std::sync::Arc;
use std::time::Duration;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use carbide_uuid::machine::MachineId;

use crate::containerd::container;
use crate::containerd::container::ContainerSummary;

#[derive(Debug, Clone)]
pub struct MachineInventoryUpdaterConfig {
    pub dpu_agent_version: String,
    /// How often to update the inventory
    pub update_inventory_interval: Duration,
    pub machine_id: MachineId,
    pub forge_api: String,
    pub forge_client_config: Arc<ForgeClientConfig>,
}

pub async fn single_run(config: &MachineInventoryUpdaterConfig) -> eyre::Result<()> {
    tracing::trace!(
        "Updating machine inventory for machine: {}",
        config.machine_id
    );

    let containers = container::Containers::list().await?;

    let images = container::Images::list().await?;

    tracing::trace!("Containers: {:?}", containers);

    let machine_id = config.machine_id;

    let mut result: Vec<ContainerSummary> = Vec::new();

    // Map container images to container names
    for mut c in containers.containers {
        let images_clone = images.clone();
        let images_names = images_clone.find_by_id(&c.image.id)?;
        c.image_ref = images_names.names;
        result.push(c);
    }

    let mut inventory: Vec<rpc::MachineInventorySoftwareComponent> = result
        .into_iter()
        .flat_map(|c| {
            c.image_ref
                .into_iter()
                .map(|n| rpc::MachineInventorySoftwareComponent {
                    name: n.name.clone(),
                    version: n.version.clone(),
                    url: n.repository,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // Add the DPU agent version to the inventory
    inventory.push(rpc::MachineInventorySoftwareComponent {
        name: "forge-dpu-agent".to_string(),
        version: config.dpu_agent_version.clone(),
        url: String::new(),
    });

    let inventory = rpc::MachineInventory {
        components: inventory,
    };

    let agent_report = rpc::DpuAgentInventoryReport {
        machine_id: Some(machine_id),
        inventory: Some(inventory),
    };

    if let Err(e) = update_agent_reported_inventory(
        agent_report,
        &config.forge_client_config,
        &config.forge_api,
    )
    .await
    {
        tracing::error!(
            "Error while executing update_agent_reported_inventory: {:#}",
            e
        );
    } else {
        tracing::debug!("Successfully updated machine inventory");
    }

    Ok(())
}

async fn update_agent_reported_inventory(
    inventory_report: rpc::DpuAgentInventoryReport,
    client_config: &forge_tls_client::ForgeClientConfig,
    forge_api: &str,
) -> eyre::Result<()> {
    let mut client = match forge_tls_client::ForgeTlsClient::retry_build(&ApiConfig::new(
        forge_api,
        client_config,
    ))
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

    tracing::trace!("update_machine_inventory: {:?}", inventory_report);

    let request = tonic::Request::new(inventory_report);
    match client.update_agent_reported_inventory(request).await {
        Ok(response) => {
            tracing::trace!("update_agent_reported_inventory response: {:?}", response);
            Ok(())
        }
        Err(err) => Err(eyre::eyre!(
            "Error while executing the update_agent_reported_inventory gRPC call: {}",
            err.to_string()
        )),
    }
}
