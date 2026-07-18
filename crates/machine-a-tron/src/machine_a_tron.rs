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

use bmc_mock::mac_address_pool::PoolConfig as MacAddressPoolConfig;
use bmc_mock::{HostHardwareType, HostMachineInfo};
use futures::future::try_join_all;
use rpc::forge::{DpuMode, ExpectedHostNic, NetworkSegmentType, VpcVirtualizationType};
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

fn expected_host_nics(
    host_info: &HostMachineInfo,
    dpu_mode: Option<DpuMode>,
) -> Vec<ExpectedHostNic> {
    let mac_addresses = match dpu_mode {
        Some(DpuMode::NicMode) => host_info
            .dpus
            .iter()
            .map(|dpu| dpu.host_mac_address)
            .collect::<Vec<_>>(),
        Some(DpuMode::NoDpu) => host_info.non_dpu_mac_address.into_iter().collect(),
        _ => Vec::new(),
    };

    mac_addresses
        .into_iter()
        .enumerate()
        .map(|(index, mac_address)| ExpectedHostNic {
            mac_address: mac_address.to_string(),
            nic_type: None,
            fixed_ip: None,
            fixed_mask: None,
            fixed_gateway: None,
            primary: Some(index == 0),
            network_segment_type: Some(NetworkSegmentType::HostInband as i32),
        })
        .collect()
}

impl MachineATron {
    pub fn new(app_context: Arc<MachineATronContext>) -> Self {
        Self { app_context }
    }

    pub async fn make_machines(&self, paused: bool) -> eyre::Result<Vec<HostMachineHandle>> {
        self.app_context.app_config.validate()?;

        for (machine_group, machine) in &self.app_context.app_config.machines {
            if machine.missing_host_inband_relay_for_direct_host_dhcp() {
                tracing::warn!(
                    machine_group,
                    dpu_per_host_count = machine.dpu_per_host_count,
                    dpus_in_nic_mode = machine.dpus_in_nic_mode,
                    admin_dhcp_relay_address = %machine.admin_dhcp_relay_address,
                    "host_inband_dhcp_relay_address is not configured for a zero-DPU or NIC-mode host; direct host DHCP will fall back to admin_dhcp_relay_address"
                );
            }
        }

        let mut persisted_machines = self
            .app_context
            .app_config
            .read_persisted_machines()
            .inspect_err(|e| {
                tracing::info!(error=?e, "could not read persisted machines, may be the first run")
            })
            .unwrap_or_default();

        // If we've persisted the machine info on a previous run, use that.
        // Reserve all persisted MACs before allocating anything new, so recovery
        // is independent of config iteration order.
        let machines = {
            let mut mac_address_pool = self.app_context.mac_address_pool.lock().unwrap();

            if let Some(persisted_machines) = persisted_machines.as_ref() {
                for persisted in persisted_machines.values().flatten() {
                    let hw_mac_address_ranges = persisted
                        .hw_mac_addr_pool
                        .as_ref()
                        .map(|pool| MacAddressPoolConfig::new(pool.base, pool.host_bits))
                        .transpose()?;
                    if let Some(hw_mac_address_ranges) = hw_mac_address_ranges {
                        mac_address_pool.reserve_range_config(hw_mac_address_ranges)?;
                    }
                    persisted
                        .mac_addresses()
                        .filter(|addr| {
                            !hw_mac_address_ranges.is_some_and(|range| range.contains(*addr))
                        })
                        .map(|addr| mac_address_pool.reserve(addr))
                        .collect::<Result<Vec<_>, _>>()?;
                }
            }

            self.app_context
                .app_config
                .machines
                .iter()
                .flat_map(|(config_name, config)| {
                    if let Some(persisted_machines) = persisted_machines
                        .as_mut()
                        .and_then(|m| m.remove(config_name.as_str()))
                    {
                        tracing::info!(
                            config_name = %config_name,
                            "Recovering persisted machines",
                        );
                        persisted_machines
                            .into_iter()
                            .map(|persisted| -> eyre::Result<HostMachineHandle> {
                                let hw_mac_address_ranges = persisted
                                    .hw_mac_addr_pool
                                    .as_ref()
                                    .map(|pool| {
                                        MacAddressPoolConfig::new(pool.base, pool.host_bits)
                                    })
                                    .unwrap_or_else(|| mac_address_pool.allocate_range_config())?;
                                let host_machine = HostMachine::from_persisted(
                                    persisted,
                                    config_name.clone(),
                                    self.app_context.clone(),
                                    config.clone(),
                                    hw_mac_address_ranges,
                                );

                                Ok(host_machine.start(paused))
                            })
                            .collect::<Vec<_>>()
                    } else {
                        tracing::info!(
                            config_name = %config_name,
                            "Constructing machines",
                        );
                        (0..config.host_count)
                            .map(|_| {
                                let mac_range = mac_address_pool.allocate_range_config()?;
                                let host_machine = HostMachine::new(
                                    self.app_context.clone(),
                                    config_name.clone(),
                                    config.clone(),
                                    &mut mac_address_pool,
                                    mac_range,
                                );

                                Ok(host_machine.start(paused))
                            })
                            .collect::<Vec<_>>()
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        if self.app_context.app_config.register_expected_machines {
            for (rack_id, rack) in &self.app_context.app_config.racks {
                self.app_context
                    .api_client()
                    .ensure_expected_rack(rack_id.clone(), rack.rack_profile_id.clone())
                    .await?;
            }

            for machine in &machines {
                let host_info = machine.host_info();
                let machine_config = self
                    .app_context
                    .app_config
                    .machines
                    .get(machine.machine_config_section())
                    .expect("machine was constructed from a configured machine group");
                let rack_id = machine_config.rack_id.clone();
                let result = match host_info.hw_type {
                    HostHardwareType::LiteOnPowerShelf | HostHardwareType::DeltaPowerShelf => {
                        self.app_context
                            .api_client()
                            .add_expected_power_shelf(
                                host_info.bmc_mac_address.to_string(),
                                host_info.serial.clone(),
                                rack_id,
                            )
                            .await
                    }
                    HostHardwareType::NvidiaSwitchNd5200Ld => {
                        self.app_context
                            .api_client()
                            .add_expected_switch(
                                host_info.bmc_mac_address.to_string(),
                                host_info
                                    .switch_serial_number
                                    .clone()
                                    .unwrap_or_else(|| host_info.serial.clone()),
                                host_info
                                    .nvos_mac_addresses
                                    .iter()
                                    .map(|mac| mac.to_string())
                                    .collect(),
                                rack_id,
                            )
                            .await
                    }
                    _ => {
                        // Derive the expected `dpu_mode` from the machine's
                        // MachineConfig: zero-DPU hosts declare `NoDpu`, hosts
                        // running their DPUs as NICs declare `NicMode`, everything
                        // else defers to the absolute default (DpuMode).
                        // Site-explorer's ingestion gate requires this explicit
                        // declaration for any host without DPU PCIe devices.
                        let dpu_mode = if machine_config.dpu_per_host_count == 0 {
                            Some(DpuMode::NoDpu)
                        } else if machine_config.dpus_in_nic_mode {
                            Some(DpuMode::NicMode)
                        } else {
                            None
                        };
                        let host_nics = expected_host_nics(host_info, dpu_mode);
                        self.app_context
                            .api_client()
                            .add_expected_machine(
                                host_info.bmc_mac_address.to_string(),
                                host_info.serial.clone(),
                                rack_id,
                                dpu_mode,
                                host_nics,
                            )
                            .await
                    }
                };

                result
                    .inspect_err(|e| {
                        tracing::warn!(
                            error=?e,
                            hardware_type = %host_info.hw_type,
                            "error adding expected inventory record, likely already ingested"
                        );
                    })
                    .ok();
            }
        } else {
            tracing::info!(
                machine_count = machines.len(),
                "register_expected_machines=false; skipping auto-registration of mock host(s)",
            );
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
            tracing::info!(
                bmc_proxy_address = %host_port_str,
                "Configuring carbide API to use as bmc_proxy",
            );
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
            let network_virtualization_type =
                parse_network_virtualization_type(config.network_virtualization_type.as_deref());
            for _ in 0..config.vpc_count {
                let app_context = self.app_context.clone();
                let vpc = Vpc::new(
                    app_context,
                    tui_event_tx.clone(),
                    network_virtualization_type,
                )
                .await;

                for _ in 0..config.subnets_per_vpc {
                    let app_context = self.app_context.clone();

                    match Subnet::new(app_context, tui_event_tx.clone(), &vpc).await {
                        Ok(subnet) => {
                            subnet_handles.push(subnet);
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Error creating network segment",
                            );
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
                            tracing::info!(
                                error = %e,
                                "allocate_instance failed",
                            );
                        }
                    };
                }
            }
        }

        // Following block does not remove the entries from the VPC table due to possible references by other places.
        // It rather soft deletes the VPCs by updating the deleted column of a vpc.
        if self.app_context.app_config.cleanup_on_quit {
            for vpc in vpc_handles {
                tracing::info!(
                    vpc_id = %vpc.vpc_id,
                    "Attempting to delete VPC from database",
                );
                if let Err(e) = self
                    .app_context
                    .forge_api_client
                    .delete_vpc(vpc.vpc_id)
                    .await
                {
                    tracing::error!(
                        error = %e,
                        "Delete VPC API call failed",
                    )
                }
            }

            for subnet in subnet_handles {
                tracing::info!(
                    network_segment_id = %subnet.segment_id,
                    "Attempting to delete network segment from database",
                );
                if let Err(e) = self
                    .app_context
                    .forge_api_client
                    .delete_network_segment(subnet.segment_id)
                    .await
                {
                    tracing::error!(
                        error = %e,
                        "Delete network segment API call failed",
                    )
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

fn parse_network_virtualization_type(s: Option<&str>) -> Option<VpcVirtualizationType> {
    match s {
        Some("etv") => Some(VpcVirtualizationType::EthernetVirtualizer),
        #[allow(deprecated)]
        Some("etv_nvue") => Some(VpcVirtualizationType::EthernetVirtualizerWithNvue),
        Some("fnn") => Some(VpcVirtualizationType::Fnn),
        Some(other) => {
            tracing::warn!(
                network_virtualization_type = other,
                "Unknown network_virtualization_type, defaulting to None (ETV)"
            );
            None
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bmc_mock::{DpuMachineInfo, DpuSettings};
    use carbide_test_support::{Check, check_values};
    use mac_address::MacAddress;

    use super::*;

    fn mac(value: &str) -> MacAddress {
        MacAddress::from_str(value).unwrap()
    }

    fn host_info(dpu_host_macs: &[MacAddress], non_dpu_mac: Option<MacAddress>) -> HostMachineInfo {
        HostMachineInfo {
            hw_type: HostHardwareType::WiwynnGB200Nvl,
            bmc_mac_address: mac("02:00:00:00:00:f0"),
            serial: "test-host".to_string(),
            dpus: dpu_host_macs
                .iter()
                .enumerate()
                .map(|(index, host_mac_address)| DpuMachineInfo {
                    hw_type: HostHardwareType::WiwynnGB200Nvl,
                    bmc_mac_address: mac(&format!("02:00:00:00:10:{index:02x}")),
                    host_mac_address: *host_mac_address,
                    oob_mac_address: mac(&format!("02:00:00:00:20:{index:02x}")),
                    serial: format!("test-dpu-{index}"),
                    settings: DpuSettings::default(),
                })
                .collect(),
            non_dpu_mac_address: non_dpu_mac,
            nvos_mac_addresses: Vec::new(),
            switch_serial_number: None,
            hw_mac_addr_pool: MacAddressPoolConfig::new(mac("0a:00:00:00:00:00"), 24).unwrap(),
            delta_psu_power: None,
        }
    }

    fn expected_nic(mac_address: MacAddress, primary: bool) -> ExpectedHostNic {
        ExpectedHostNic {
            mac_address: mac_address.to_string(),
            nic_type: None,
            fixed_ip: None,
            fixed_mask: None,
            fixed_gateway: None,
            primary: Some(primary),
            network_segment_type: Some(NetworkSegmentType::HostInband as i32),
        }
    }

    #[test]
    fn expected_host_nic_derivation() {
        let first_dpu_mac = mac("02:00:00:00:00:01");
        let second_dpu_mac = mac("02:00:00:00:00:02");
        let integrated_mac = mac("02:00:00:00:00:03");

        check_values(
            [
                Check {
                    scenario: "NIC-mode host declares every host-facing DPU PF",
                    input: (
                        host_info(&[first_dpu_mac, second_dpu_mac], None),
                        Some(DpuMode::NicMode),
                    ),
                    expect: vec![
                        expected_nic(first_dpu_mac, true),
                        expected_nic(second_dpu_mac, false),
                    ],
                },
                Check {
                    scenario: "zero-DPU host declares its integrated NIC",
                    input: (host_info(&[], Some(integrated_mac)), Some(DpuMode::NoDpu)),
                    expect: vec![expected_nic(integrated_mac, true)],
                },
                Check {
                    scenario: "managed-DPU host relies on automatic DPU discovery",
                    input: (host_info(&[first_dpu_mac], None), None),
                    expect: Vec::new(),
                },
            ],
            |(host_info, dpu_mode)| expected_host_nics(&host_info, dpu_mode),
        );
    }
}
