/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::HashSet;
use std::sync::Arc;

use futures::future::try_join_all;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::PersistedHostMachine;
use crate::config::MachineATronContext;
use crate::host_machine::{HostMachine, HostMachineHandle};
use crate::machine_utils::get_next_free_machine;
use crate::subnet::Subnet;
use crate::tui::UiUpdate;
use crate::vpc::Vpc;

#[derive(PartialEq, Eq)]
pub enum AppEvent {
    Quit,
    AllocateInstance,
}

pub struct MachineATron {
    app_context: Arc<MachineATronContext>,
}

impl MachineATron {
    pub fn new(app_context: Arc<MachineATronContext>) -> Self {
        Self { app_context }
    }

    pub async fn make_machines(&self, paused: bool) -> eyre::Result<Vec<HostMachineHandle>> {
        let mut persisted_machines = self
            .app_context
            .app_config
            .read_persisted_machines()
            .inspect_err(|e| {
                tracing::info!(error=?e, "could not read persisted machines, may be the first run")
            })
            .unwrap_or_default();

        // If we've persisted the machine info on a previous run, use that
        let machines: Vec<HostMachineHandle> = self
            .app_context
            .app_config
            .machines
            .iter()
            .flat_map(|(config_name, config)| {
                if let Some(persisted_machines) = persisted_machines
                    .as_mut()
                    .and_then(|m| m.remove(config_name.as_str()))
                {
                    tracing::info!("Recovering persisted machines for config {}", config_name);
                    persisted_machines
                        .into_iter()
                        .map(|persisted| {
                            let host_machine = HostMachine::from_persisted(
                                persisted,
                                config_name.clone(),
                                self.app_context.clone(),
                                config.clone(),
                            );

                            host_machine.start(paused)
                        })
                        .collect::<Vec<_>>()
                } else {
                    tracing::info!("Constructing machines for config {}", config_name);
                    (0..config.host_count)
                        .map(move |_| {
                            let host_machine = HostMachine::new(
                                self.app_context.clone(),
                                config_name.clone(),
                                config.clone(),
                            );

                            host_machine.start(paused)
                        })
                        .collect::<Vec<_>>()
                }
            })
            .collect();

        for machine in &machines {
            // Inform the API that we have finished our reboot (ie. scout is now running)
            self.app_context
                .api_client()
                .add_expected_machine(
                    machine.host_info().bmc_mac_address.to_string(),
                    machine.host_info().serial.clone(),

                )
                .await
                .inspect_err(|e| {
                    tracing::warn!(error=?e, "error adding expected machine, likely already ingested");
                })
                .ok();
        }

        Ok(machines)
    }

    pub async fn run(
        &mut self,
        machine_handles: Vec<HostMachineHandle>,
        tui_event_tx: Option<mpsc::Sender<UiUpdate>>,
        mut app_rx: mpsc::Receiver<AppEvent>,
    ) -> eyre::Result<()> {
        let mut vpc_handles: Vec<Vpc> = Vec::new();
        let mut subnet_handles: Vec<Subnet> = Vec::new();
        // Represents the mat_id of machines which are Assigned to a forge Instance
        let mut assigned_mat_ids: HashSet<Uuid> = HashSet::new();

        if let Some(host_str) = self
            .app_context
            .app_config
            .configure_carbide_bmc_proxy_host
            .as_ref()
        {
            let host_port_str =
                format!("{}:{}", host_str, self.app_context.app_config.bmc_mock_port);
            tracing::info!("Configuring carbide API to use {host_port_str} as bmc_proxy",);
            _ = self
                .app_context
                .api_client()
                .configure_bmc_proxy_host(host_port_str)
                .await
                .inspect_err(
                    |e| tracing::warn!(error = ?e, "Could not configure carbide bmc_proxy"),
                )
        }

        for (_config_name, config) in self.app_context.app_config.machines.iter() {
            for _ in 0..config.vpc_count {
                let app_context = self.app_context.clone();
                let vpc = Vpc::new(app_context, tui_event_tx.clone()).await;

                for _ in 0..config.subnets_per_vpc {
                    let app_context = self.app_context.clone();

                    match Subnet::new(app_context, tui_event_tx.clone(), &vpc.vpc_name).await {
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

        for machine_handle in &machine_handles {
            machine_handle.attach_to_tui(tui_event_tx.clone())?;
            machine_handle.resume()?;
        }

        tracing::info!("Machine construction complete");

        while let Some(msg) = app_rx.recv().await {
            match msg {
                AppEvent::Quit => {
                    tracing::info!("quit");
                    let persisted_machines = if self.app_context.app_config.cleanup_on_quit {
                        try_join_all(machine_handles.into_iter().map(|m| {
                            let api_client = self.app_context.api_client();
                            let persisted = m.persisted();
                            m.abort();
                            async move {
                                m.delete_from_api(api_client).await?;
                                Ok::<PersistedHostMachine, eyre::Report>(persisted)
                            }
                        }))
                        .await?
                    } else {
                        machine_handles
                            .into_iter()
                            .map(|m| {
                                m.abort();
                                m.persisted()
                            })
                            .collect()
                    };

                    // Persist the current state of the machines before quitting
                    self.app_context
                        .app_config
                        .write_persisted_machines(&persisted_machines)?;

                    break;
                }

                AppEvent::AllocateInstance => {
                    tracing::info!("Allocating an instance.");

                    let Some(free_machine) =
                        get_next_free_machine(&machine_handles, &assigned_mat_ids).await
                    else {
                        tracing::error!("No available machines.");
                        continue;
                    };

                    let Some(hid_for_instance) = free_machine.observed_machine_id() else {
                        tracing::error!("Machine in state Ready but with no machine ID?");
                        continue;
                    };

                    // TODO: Remove the hardcoded subnet_0 to be user specified through CLI.
                    match self
                        .app_context
                        .api_client()
                        .allocate_instance(hid_for_instance, "subnet_0")
                        .await
                    {
                        Ok(_) => {
                            assigned_mat_ids.insert(free_machine.mat_id());
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
        if self.app_context.app_config.cleanup_on_quit {
            for vpc in vpc_handles {
                tracing::info!("Attempting to delete VPC with id: {} from db.", vpc.vpc_id);
                if let Err(e) = self
                    .app_context
                    .forge_api_client
                    .delete_vpc(vpc.vpc_id)
                    .await
                {
                    tracing::error!("Delete VPC Api call failed with {}", e)
                }
            }

            for subnet in subnet_handles {
                tracing::info!(
                    "Attempting to delete network segment with id: {} from db.",
                    subnet.segment_id
                );
                if let Err(e) = self
                    .app_context
                    .forge_api_client
                    .delete_network_segment(subnet.segment_id)
                    .await
                {
                    tracing::error!("Delete network segment Api call failed with {}", e)
                }
            }
        }

        if self
            .app_context
            .app_config
            .configure_carbide_bmc_proxy_host
            .is_some()
        {
            tracing::info!("Removing bmc_proxy configuration from carbide API");
            _ = self
                .app_context
                .api_client()
                .configure_bmc_proxy_host("".to_string())
                .await
                .inspect_err(
                    |e| tracing::warn!(error = ?e, "Could not configure carbide bmc_proxy"),
                )
        }

        tracing::info!("machine-a-tron finished");
        Ok(())
    }
}
