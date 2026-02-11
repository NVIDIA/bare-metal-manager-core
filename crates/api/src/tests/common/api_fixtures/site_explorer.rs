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
use std::collections::HashMap;
use std::future::Future;
use std::iter;
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use db::machine_interface::find_by_mac_address;
use db::{DatabaseError, power_shelf as db_power_shelf, rack as db_rack, switch as db_switch};
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use futures_util::FutureExt;
use health_report::HealthReport;
use mac_address::MacAddress;
use model::hardware_info::HardwareInfo;
use model::machine::{
    BomValidating, BomValidatingContext, DpfState, DpuInitState, FailureCause, FailureDetails,
    FailureSource, LockdownInfo, LockdownMode, LockdownState, MachineState, MachineValidatingState,
    ManagedHostState, ManagedHostStateSnapshot, MeasuringState, ValidationState,
};
use model::power_shelf::power_shelf_id::from_hardware_info;
use model::power_shelf::{NewPowerShelf, PowerShelfConfig};
use model::rack::RackConfig;
use model::site_explorer::EndpointExplorationReport;
use model::switch::switch_id::from_hardware_info as switch_from_hardware_info;
use model::switch::{NewSwitch, SwitchConfig};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self, HardwareHealthReport};
use rpc::forge_agent_control_response::Action;
use rpc::machine_discovery::AttestKeyInfo;
use rpc::{DiscoveryData, DiscoveryInfo};
use sqlx::PgConnection;
use tonic::Request;
use uuid;

use super::dpu::create_machine_inventory;
use super::tpm_attestation::{AK_NAME_SERIALIZED, AK_PUB_SERIALIZED, EK_PUB_SERIALIZED};
use super::{discovery_completed, inject_machine_measurements, network_configured};
use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::host::host_uefi_setup;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY,
};
use crate::tests::common::api_fixtures::{
    TestEnv, TestManagedHost, forge_agent_control, get_machine_validation_runs,
    machine_validation_completed, persist_machine_validation_result, reboot_completed,
    update_machine_validation_run,
};
use crate::tests::common::rpc_builder::DhcpDiscovery;

/// MockExploredHost presents a fluent interface for declaring a mock host and running it through
/// the site-explorer ingestion lifecycle. Its methods are intended to be chained together to
/// script together a sequence of expected events to ingest a mock host.
pub struct MockExploredHost<'a> {
    pub test_env: &'a TestEnv,
    pub managed_host: ManagedHostConfig,
    pub host_bmc_ip: Option<IpAddr>,
    pub dpu_bmc_ips: HashMap<u8, IpAddr>,
    pub host_dhcp_response: Option<forge::DhcpRecord>,
    pub machine_discovery_response: Option<forge::MachineDiscoveryResult>,
    pub dpu_machine_ids: HashMap<u8, MachineId>,
}

impl MockExploredHost<'_> {
    pub fn discovered_machine_id(&self) -> Option<MachineId> {
        self.machine_discovery_response
            .as_ref()
            .and_then(|r| r.machine_id)
    }
}

impl<'a> MockExploredHost<'a> {
    pub fn new(test_env: &'a TestEnv, managed_host: ManagedHostConfig) -> Self {
        Self {
            test_env,
            managed_host,
            host_bmc_ip: None,
            dpu_bmc_ips: HashMap::new(),
            host_dhcp_response: None,
            machine_discovery_response: None,
            dpu_machine_ids: HashMap::new(),
        }
    }

    /// Simulate the host's BMC interface getting DHCP.
    ///
    /// Yields the result to the passed closure.
    pub async fn discover_dhcp_host_bmc<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        let result = self
            .test_env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(
                    self.managed_host.bmc_mac_address,
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip(),
                )
                .vendor_string("SomeVendor")
                .tonic_request(),
            )
            .await;

        if let Ok(ref response) = result {
            self.host_bmc_ip = Some(response.get_ref().address.parse()?);
        }

        f(result, &mut self)?;
        Ok(self)
    }

    /// Simulate the given DPU's (indicated by dpu_index) BMC interface getting DHCP. Will panic if
    /// the index is out of range (ie. not part of the ManagedHostConfig.)
    ///
    /// Yields the result to the passed closure.
    pub async fn discover_dhcp_dpu_bmc<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        dpu_index: u8,
        f: F,
    ) -> eyre::Result<Self> {
        let result = self
            .test_env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(
                    self.managed_host.dpus[dpu_index as usize].bmc_mac_address,
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip(),
                )
                .vendor_string("SomeVendor")
                .tonic_request(),
            )
            .await;

        if let Ok(ref response) = result {
            self.dpu_bmc_ips
                .insert(dpu_index, response.get_ref().address.parse()?);
        }

        f(result, &mut self)?;
        Ok(self)
    }

    // Create an EndpointExplorationReport for the host and DPUs, and seed them into the
    // MockEndpointExplorer in this test env. If any of the host BMC or DPU BMC's have not run DHCP
    // yet, they will be skipped (as we won't yet know their IP.)
    pub fn insert_site_exploration_results(mut self) -> eyre::Result<Self> {
        self.test_env.endpoint_explorer.insert_endpoints(
            self.managed_host
                .dpus
                .iter()
                .enumerate()
                .filter_map(|(index, dpu)| {
                    let mut report: EndpointExplorationReport = dpu.clone().into();
                    report.generate_machine_id(false).unwrap();
                    self.dpu_machine_ids
                        .insert(index.try_into().unwrap(), report.machine_id.unwrap());
                    Some((*self.dpu_bmc_ips.get(&(index as u8))?, dpu.clone().into()))
                })
                .chain(
                    iter::once(
                        self.host_bmc_ip
                            .map(|ip| (ip, self.managed_host.clone().into())),
                    )
                    .flatten(),
                )
                .collect(),
        );
        Ok(self)
    }

    /// Run DHCP on the host's primary interface. If there are DPU's in the ManagedHostConfig, it
    /// uses the host_nics of the first DPU. If there are no DPUs, it uses the first mac
    /// address in [`ManagedHostConfig#non_dpu_macs`]. If there are none of those, panics.
    ///
    /// Yields the DHCP result to the passed closure
    pub async fn discover_dhcp_host_primary_iface<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        // Run dhcp from primary interface
        let relay_address = if self.managed_host.dpus.is_empty() {
            // zero-DPU machines DHCP from a HostInband segment
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.ip().to_string()
        } else {
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip().to_string()
        };

        let result = self
            .test_env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(self.managed_host.dhcp_mac_address(), relay_address)
                    .vendor_string("Bluefield")
                    .tonic_request(),
            )
            .await;
        if let Ok(ref response) = result {
            self.host_dhcp_response = Some(response.get_ref().clone());
        }
        f(result, &mut self)?;
        Ok(self)
    }

    pub async fn discover_dhcp_dpu_primary_iface(self, dpu_index: u8) -> Self {
        let _ = self
            .test_env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(
                    self.managed_host.dpus[dpu_index as usize].oob_mac_address,
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip(),
                )
                .vendor_string("SomeVendor")
                .tonic_request(),
            )
            .await;

        self
    }

    /// Run DHCP on the specified non-dpu host index ID, if available, from the given relay address.
    pub async fn discover_dhcp_host_secondary_iface<
        F: FnOnce(tonic::Result<tonic::Response<forge::DhcpRecord>>, &mut Self) -> eyre::Result<()>,
    >(
        mut self,
        iface_index: u8,
        relay_address: String,
        f: F,
    ) -> eyre::Result<Self> {
        let mac_address = self.managed_host.non_dpu_macs[iface_index as usize].to_string();
        let result = self
            .test_env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(mac_address, relay_address)
                    .vendor_string("Bluefield")
                    .tonic_request(),
            )
            .await;
        if let Ok(ref response) = result {
            self.host_dhcp_response = Some(response.get_ref().clone());
        }
        f(result, &mut self)?;
        Ok(self)
    }

    /// Simulates scout running machine discovery on the managed host.
    ///
    /// Yields the discovery result to the passed closure.
    pub async fn discover_machine<
        F: FnOnce(
            tonic::Result<tonic::Response<forge::MachineDiscoveryResult>>,
            &mut Self,
        ) -> eyre::Result<()>,
    >(
        mut self,
        f: F,
    ) -> eyre::Result<Self> {
        // Run scout discovery from the host

        let mut discovery_info =
            DiscoveryInfo::try_from(HardwareInfo::from(&self.managed_host)).unwrap();

        discovery_info.attest_key_info = Some(AttestKeyInfo {
            ek_pub: EK_PUB_SERIALIZED.to_vec(),
            ak_pub: AK_PUB_SERIALIZED.to_vec(),
            ak_name: AK_NAME_SERIALIZED.to_vec(),
        });

        let result = self
            .test_env
            .api
            .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
                machine_interface_id: Some(
                    *self
                        .host_dhcp_response
                        .as_ref()
                        .unwrap()
                        .machine_interface_id
                        .as_ref()
                        .unwrap(),
                ),
                create_machine: true,
                discovery_data: Some(DiscoveryData::Info(discovery_info)),
            }))
            .await;

        if let Ok(ref response) = result {
            self.machine_discovery_response = Some(response.get_ref().clone());
        }

        f(result, &mut self)?;
        Ok(self)
    }

    /// Runs one iteration of site explorer in the test env.
    pub async fn run_site_explorer_iteration(self) -> Self {
        self.test_env.run_site_explorer_iteration().await;
        self
    }

    /// Runs dpu_state_controller with DPF.
    pub async fn dpu_state_controller_iterations_with_dpf(self) -> Self {
        if self.managed_host.dpus.is_empty() {
            return self;
        }

        let mut txn = self.test_env.pool.begin().await.unwrap();

        let host_machine_id =
            db::machine::find_host_by_dpu_machine_id(&mut txn, &self.dpu_machine_ids[&0].clone())
                .await
                .unwrap()
                .unwrap()
                .id;

        for machine_id in self.dpu_machine_ids.values() {
            create_machine_inventory(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10 + (10 * self.dpu_machine_ids.len() as u32),
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| {
                                (
                                    machine_id,
                                    DpuInitState::DpfStates {
                                        state: DpfState::WaitingForOsInstallToComplete,
                                    },
                                )
                            })
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        //run scout discovery for dpu(s)
        for dpu in self.managed_host.dpus.clone() {
            let machine_interfaces = find_by_mac_address(&mut txn, dpu.oob_mac_address)
                .await
                .unwrap();
            let primary_interface = machine_interfaces
                .iter()
                .find(|interface| interface.primary_interface)
                .unwrap();
            let _ = self
                .test_env
                .api
                .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
                    machine_interface_id: Some(primary_interface.id),
                    create_machine: true,
                    discovery_data: Some(DiscoveryData::Info(
                        DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
                    )),
                }))
                .await;
        }

        for machine_id in self.dpu_machine_ids.values() {
            let response = forge_agent_control(self.test_env, *machine_id).await;
            assert_eq!(
                response.action,
                rpc::forge_agent_control_response::Action::Discovery as i32
            );

            discovery_completed(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10 + (10 * self.dpu_machine_ids.len() as u32),
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| {
                                (
                                    machine_id,
                                    DpuInitState::DpfStates {
                                        state: DpfState::WaitForNetworkConfigAndRemoveAnnotation,
                                    },
                                )
                            })
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        network_configured(
            self.test_env,
            &self.dpu_machine_ids.values().copied().collect(),
        )
        .await;

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                35,
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| (machine_id, DpuInitState::WaitingForNetworkConfig))
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        txn.commit().await.unwrap();

        network_configured(
            self.test_env,
            &self.dpu_machine_ids.values().copied().collect(),
        )
        .await;

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                4,
                ManagedHostState::HostInit {
                    machine_state: MachineState::EnableIpmiOverLan,
                },
            )
            .await;

        self
    }
    /// Runs dpu_state_controller
    pub async fn dpu_state_controller_iterations(self) -> Self {
        if self.managed_host.dpus.is_empty() {
            return self;
        }

        let mut txn = self.test_env.pool.begin().await.unwrap();

        let host_machine_id =
            db::machine::find_host_by_dpu_machine_id(&mut txn, &self.dpu_machine_ids[&0].clone())
                .await
                .unwrap()
                .unwrap()
                .id;

        for machine_id in self.dpu_machine_ids.values() {
            create_machine_inventory(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10 + (10 * self.dpu_machine_ids.len() as u32),
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| (machine_id, DpuInitState::Init))
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        //run scout discovery for dpu(s)
        for dpu in self.managed_host.dpus.clone() {
            let machine_interfaces = find_by_mac_address(&mut txn, dpu.oob_mac_address)
                .await
                .unwrap();
            let primary_interface = machine_interfaces
                .iter()
                .find(|interface| interface.primary_interface)
                .unwrap();
            let _ = self
                .test_env
                .api
                .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
                    machine_interface_id: Some(primary_interface.id),
                    create_machine: true,
                    discovery_data: Some(DiscoveryData::Info(
                        DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
                    )),
                }))
                .await;
        }

        for machine_id in self.dpu_machine_ids.values() {
            let response = forge_agent_control(self.test_env, *machine_id).await;
            assert_eq!(
                response.action,
                rpc::forge_agent_control_response::Action::Discovery as i32
            );

            discovery_completed(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                35,
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| (machine_id, DpuInitState::WaitingForNetworkConfig))
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        txn.commit().await.unwrap();

        network_configured(
            self.test_env,
            &self.dpu_machine_ids.values().copied().collect(),
        )
        .await;

        // Wait until we exit the DPU states
        self.test_env
            .run_machine_state_controller_iteration_until_state_condition(
                &host_machine_id,
                20,
                |machine| matches!(*machine.current_state(), ManagedHostState::HostInit { .. }),
            )
            .await;

        self
    }

    pub async fn dpu_state_controller_iterations_to_network_install(self) -> Self {
        if self.managed_host.dpus.is_empty() {
            return self;
        }

        let mut txn = self.test_env.pool.begin().await.unwrap();

        let host_machine_id =
            db::machine::find_host_by_dpu_machine_id(&mut txn, &self.dpu_machine_ids[&0].clone())
                .await
                .unwrap()
                .unwrap()
                .id;

        for machine_id in self.dpu_machine_ids.values() {
            create_machine_inventory(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                25,
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| (machine_id, DpuInitState::Init))
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        //run scout discovery for dpu(s)
        for dpu in self.managed_host.dpus.clone() {
            let machine_interfaces = find_by_mac_address(&mut txn, dpu.oob_mac_address)
                .await
                .unwrap();
            let primary_interface = machine_interfaces
                .iter()
                .find(|interface| interface.primary_interface)
                .unwrap();
            let _ = self
                .test_env
                .api
                .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
                    machine_interface_id: Some(primary_interface.id),
                    create_machine: true,
                    discovery_data: Some(DiscoveryData::Info(
                        DiscoveryInfo::try_from(HardwareInfo::from(&dpu)).unwrap(),
                    )),
                }))
                .await;
        }

        for machine_id in self.dpu_machine_ids.values() {
            discovery_completed(self.test_env, *machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                35,
                ManagedHostState::DPUInit {
                    dpu_states: model::machine::DpuInitStates {
                        states: self
                            .dpu_machine_ids
                            .clone()
                            .into_values()
                            .map(|machine_id| (machine_id, DpuInitState::WaitingForNetworkConfig))
                            .collect::<HashMap<MachineId, DpuInitState>>(),
                    },
                },
            )
            .await;

        txn.commit().await.unwrap();

        self
    }

    pub async fn host_state_controller_iterations(self) -> Self {
        let host_machine_id = self
            .machine_discovery_response
            .as_ref()
            .unwrap()
            .machine_id
            .unwrap();

        let expected_state = self.managed_host.expected_state.clone();

        if self.test_env.attestation_enabled {
            let stop_state = self
                .test_env
                .run_machine_state_controller_iteration_until_state_condition(
                    &host_machine_id,
                    10,
                    |machine| {
                        machine.current_state() == &expected_state
                            || matches!(
                                *machine.current_state(),
                                ManagedHostState::HostInit {
                                    machine_state: MachineState::Measuring {
                                        measuring_state: MeasuringState::WaitingForMeasurements,
                                    },
                                }
                            )
                    },
                )
                .await;

            // if we hit the requested state before the measuring state, return early
            if stop_state == expected_state {
                return self;
            }

            inject_machine_measurements(self.test_env, host_machine_id).await;
        }

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10,
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForDiscovery,
                },
            )
            .await;

        self.test_env
            .api
            .record_hardware_health_report(Request::new(HardwareHealthReport {
                machine_id: Some(host_machine_id),
                report: Some(HealthReport::empty("hardware-health".to_string()).into()),
            }))
            .await
            .expect("Failed to add hardware health report to newly created machine");

        discovery_completed(self.test_env, host_machine_id).await;
        self.test_env.run_ib_fabric_monitor_iteration().await;
        host_uefi_setup(self.test_env, &host_machine_id).await;

        let stop_state = self
            .test_env
            .run_machine_state_controller_iteration_until_state_condition(
                &host_machine_id,
                10,
                |machine| {
                    machine.current_state() == &expected_state
                        || matches!(
                            *machine.current_state(),
                            ManagedHostState::HostInit {
                                machine_state: MachineState::WaitingForLockdown {
                                    lockdown_info: LockdownInfo {
                                        state: LockdownState::WaitForDPUUp,
                                        mode: LockdownMode::Enable,
                                    },
                                },
                            }
                        )
                },
            )
            .await;

        if stop_state == expected_state {
            return self;
        }

        // We use forge_dpu_agent's health reporting as a signal that
        // DPU has rebooted.
        super::network_configured(
            self.test_env,
            &self.dpu_machine_ids.values().copied().collect(),
        )
        .await;

        if self.test_env.config.bom_validation.enabled
            && !self
                .test_env
                .config
                .bom_validation
                .ignore_unassigned_machines
        {
            tracing::info!("bom validation enabled");
            let stop_state = self
                .test_env
                .run_machine_state_controller_iteration_until_state_condition(
                    &host_machine_id,
                    20,
                    |machine| {
                        machine.current_state() == &expected_state
                            || machine.hw_sku.is_none()
                                && matches!(
                                    *machine.current_state(),
                                    ManagedHostState::BomValidating {
                                        bom_validating_state:
                                            BomValidating::WaitingForSkuAssignment(
                                                BomValidatingContext { .. },
                                            ),
                                    }
                                )
                            || machine.hw_sku.is_some()
                    },
                )
                .await;

            // if we hit the requested state before the BomValidating state, return early
            if stop_state == expected_state {
                return self;
            }

            let stop_state = self
                .assign_sku_if_needed(&host_machine_id, stop_state, &expected_state)
                .await;
            if stop_state == expected_state {
                return self;
            }

            // If auto_assign_sku_in_fixture is disabled and machine is stuck in WaitingForSkuAssignment,
            // don't continue waiting - return early to allow tests to inspect this state
            if !self.managed_host.auto_assign_sku_in_fixture
                && matches!(
                    stop_state,
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::WaitingForSkuAssignment(_)
                    }
                )
            {
                tracing::info!(
                    "auto_assign_sku_in_fixture=false and machine in WaitingForSkuAssignment, returning early"
                );
                return self;
            }
        }
        let stop_state =
            self.test_env
                .run_machine_state_controller_iteration_until_state_condition(
                    &host_machine_id,
                    10,
                    |machine| {
                        machine.current_state() == &expected_state
                            || matches!(
                                *machine.current_state(),
                                ManagedHostState::Validation {
                                    validation_state: ValidationState::MachineValidation {
                                        machine_validation:
                                            MachineValidatingState::MachineValidating { .. },
                                    },
                                }
                            )
                    },
                )
                .await;

        if stop_state == expected_state {
            return self;
        }

        if self.test_env.config.machine_validation_config.enabled {
            machine_validation_completed(self.test_env, &host_machine_id, None).await;
        } else {
            // need to mark as reboot completed to move it to the next state
            // even if machine validation is disabled
            reboot_completed(self.test_env, host_machine_id).await;
        }

        let stop_state = self
            .test_env
            .run_machine_state_controller_iteration_until_state_condition(
                &host_machine_id,
                10,
                |machine| {
                    machine.current_state() == &expected_state
                        || matches!(
                            *machine.current_state(),
                            ManagedHostState::HostInit {
                                machine_state: MachineState::Discovered { .. },
                            }
                        )
                },
            )
            .await;

        if stop_state == expected_state {
            return self;
        }

        let response = forge_agent_control(self.test_env, host_machine_id).await;
        assert_eq!(
            response.action,
            rpc::forge_agent_control_response::Action::Noop as i32
        );

        self.test_env
            .run_machine_state_controller_iteration_until_state_condition(
                &host_machine_id,
                1,
                |machine| {
                    let fixed_expected_state = self
                        .test_env
                        .fill_machine_information(&expected_state, machine);
                    machine.current_state() == &fixed_expected_state
                },
            )
            .await;

        self
    }
    /// Marks all BMC IP's as having completed preingestion, manually using the database.
    pub async fn mark_preingestion_complete(self) -> eyre::Result<Self> {
        let ips = self
            .dpu_bmc_ips
            .values()
            .copied()
            .chain(iter::once(self.host_bmc_ip.unwrap()))
            .collect::<Vec<_>>();
        let mut txn = self.test_env.pool.begin().await?;
        for ip in ips {
            db::explored_endpoints::set_preingestion_complete(ip, &mut txn).await?;
        }
        txn.commit().await?;
        Ok(self)
    }

    pub async fn host_state_controller_iterations_with_machine_validation(
        self,
        machine_validation_result_data: Option<rpc::forge::MachineValidationResult>,
        error: Option<String>,
    ) -> Self {
        let host_machine_id = self
            .machine_discovery_response
            .as_ref()
            .unwrap()
            .machine_id
            .unwrap();
        let mut machine_validation_result = machine_validation_result_data.unwrap_or_default();
        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10,
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForDiscovery,
                },
            )
            .await;

        self.test_env
            .api
            .record_hardware_health_report(Request::new(HardwareHealthReport {
                machine_id: Some(host_machine_id),
                report: Some(HealthReport::empty("hardware-health".to_string()).into()),
            }))
            .await
            .expect("Failed to add hardware health report to newly created machine");

        discovery_completed(self.test_env, host_machine_id).await;
        self.test_env.run_ib_fabric_monitor_iteration().await;
        host_uefi_setup(self.test_env, &host_machine_id).await;

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                5,
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForLockdown {
                        lockdown_info: LockdownInfo {
                            state: LockdownState::WaitForDPUUp,
                            mode: LockdownMode::Enable,
                        },
                    },
                },
            )
            .await;

        // We use forge_dpu_agent's health reporting as a signal that
        // DPU has rebooted.
        super::network_configured(
            self.test_env,
            &self.dpu_machine_ids.values().copied().collect(),
        )
        .await;

        self.test_env
            .run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                10,
                ManagedHostState::Validation {
                    validation_state: ValidationState::MachineValidation {
                        machine_validation: MachineValidatingState::MachineValidating {
                            context: "Discovery".to_string(),
                            id: uuid::Uuid::default(),
                            completed: 1,
                            total: 1,
                            is_enabled: self.test_env.config.machine_validation_config.enabled,
                        },
                    },
                },
            )
            .await;

        let response = forge_agent_control(self.test_env, host_machine_id).await;
        if self.test_env.config.machine_validation_config.enabled {
            let uuid = &response.data.unwrap().pair[1].value;
            let validation_id = Some(rpc::Uuid {
                value: uuid.to_owned(),
            });
            let success = update_machine_validation_run(
                self.test_env,
                validation_id.clone(),
                Some(rpc::Duration::from(std::time::Duration::from_secs(1200))),
                1,
            )
            .await;
            assert_eq!(success.message, "Success".to_string());
            let runs = get_machine_validation_runs(self.test_env, &host_machine_id, false).await;
            for run in runs.runs {
                if run.validation_id == validation_id {
                    assert_eq!(run.status.unwrap_or_default().total, 1);
                    assert_eq!(run.status.unwrap_or_default().completed_tests, 0);
                    assert_eq!(run.duration_to_complete.unwrap_or_default().seconds, 1200);
                }
            }
            machine_validation_result.validation_id = validation_id.clone();
            persist_machine_validation_result(self.test_env, machine_validation_result.clone())
                .await;
            assert_eq!(
                get_machine_validation_runs(self.test_env, &host_machine_id, false)
                    .await
                    .runs[0]
                    .end_time,
                None
            );

            machine_validation_completed(self.test_env, &host_machine_id, error.clone()).await;

            let runs = get_machine_validation_runs(self.test_env, &host_machine_id, false).await;
            for run in runs.runs {
                if run.validation_id == validation_id {
                    assert_eq!(run.status.unwrap_or_default().total, 1);
                    assert_eq!(
                        run.status.unwrap_or_default().completed_tests,
                        if machine_validation_result.exit_code != 0 {
                            0
                        } else {
                            1
                        }
                    );
                    assert_eq!(run.duration_to_complete.unwrap_or_default().seconds, 1200);
                }
            }

            if error.is_some() {
                self.test_env.run_machine_state_controller_iteration().await;

                let mut txn = self.test_env.pool.begin().await.unwrap();
                let machine = db::machine::find_one(
                    &mut txn,
                    &self.dpu_machine_ids[&0],
                    model::machine::machine_search_config::MachineSearchConfig::default(),
                )
                .await
                .unwrap()
                .unwrap();

                match machine.current_state() {
                    ManagedHostState::Failed { .. } => {}
                    s => {
                        panic!("Incorrect state: {s}");
                    }
                }

                txn.commit().await.unwrap();
            } else if machine_validation_result.exit_code == 0 {
                let _ = forge_agent_control(self.test_env, host_machine_id).await;

                self.test_env
                    .run_machine_state_controller_iteration_until_state_matches(
                        &host_machine_id,
                        10,
                        ManagedHostState::HostInit {
                            machine_state: MachineState::Discovered {
                                skip_reboot_wait: false,
                            },
                        },
                    )
                    .await;

                let response = forge_agent_control(self.test_env, host_machine_id).await;
                assert_eq!(response.action, Action::Noop as i32);
                self.test_env
                    .run_machine_state_controller_iteration_until_state_matches(
                        &host_machine_id,
                        1,
                        ManagedHostState::Ready,
                    )
                    .await;
            } else {
                self.test_env
                    .run_machine_state_controller_iteration_until_state_matches(
                        &host_machine_id,
                        1,
                        ManagedHostState::Failed {
                            details: FailureDetails {
                                cause: FailureCause::MachineValidation {
                                    err: format!("{} is failed", machine_validation_result.name),
                                },
                                failed_at: chrono::Utc::now(),
                                source: FailureSource::Scout,
                            },
                            machine_id: host_machine_id,
                            retry_count: 0,
                        },
                    )
                    .await;
            }
        } else {
            self.test_env
                .run_machine_state_controller_iteration_until_state_matches(
                    &host_machine_id,
                    10,
                    ManagedHostState::HostInit {
                        machine_state: MachineState::Discovered {
                            skip_reboot_wait: true,
                        },
                    },
                )
                .await;

            // Note: no forge_agent_control/reboot_completed call happens here, since we're skipping
            // machine validation and thus not doing an extra reboot.

            self.test_env
                .run_machine_state_controller_iteration_until_state_matches(
                    &host_machine_id,
                    1,
                    ManagedHostState::Ready,
                )
                .await;
        }

        self
    }

    /// Run the passed closure with a mutable referece to self
    pub async fn then<F, C: FnOnce(&mut Self) -> F>(mut self, f: C) -> eyre::Result<Self>
    where
        F: Future<Output = eyre::Result<()>>,
    {
        f(&mut self).await?;
        Ok(self)
    }

    /// Move self to the passed closure and return the closure's result. Useful as the final step of
    /// a method chain to return a final result.
    pub async fn finish<R, F, C: FnOnce(Self) -> F>(self, f: C) -> R
    where
        F: Future<Output = R>,
    {
        f(self).await
    }

    async fn assign_sku_if_needed(
        &self,
        host_machine_id: &MachineId,
        state: ManagedHostState,
        expected_state: &ManagedHostState,
    ) -> ManagedHostState {
        if matches!(
            state,
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext { .. },
                ),
            }
        ) {
            // Check if auto-assignment is enabled in the fixture config
            if !self.managed_host.auto_assign_sku_in_fixture {
                tracing::info!("Skipping auto SKU assignment (auto_assign_sku_in_fixture=false)");
                return state;
            }

            let mut txn = self.test_env.pool.begin().await.unwrap();
            tracing::info!("generating sku");
            let sku = db::sku::generate_sku_from_machine(txn.as_mut(), host_machine_id)
                .await
                .unwrap();
            tracing::info!("creating sku: {}", sku.id);
            db::sku::create(&mut txn, &sku).await.unwrap();

            tracing::info!("assigning sku");
            db::machine::assign_sku(&mut txn, host_machine_id, &sku.id)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            let stop_state = self
                .test_env
                .run_machine_state_controller_iteration_until_state_condition(
                    host_machine_id,
                    3,
                    |machine| {
                        machine.current_state() == expected_state
                            || matches!(
                                *machine.current_state(),
                                ManagedHostState::BomValidating {
                                    bom_validating_state: BomValidating::UpdatingInventory(
                                        BomValidatingContext { .. },
                                    ),
                                }
                            )
                    },
                )
                .await;
            // if we hit the requested state before the BomValidating state, return early
            if &stop_state == expected_state {
                return stop_state;
            }

            tracing::info!("updating inventory");
            // discovery time is based on transaction start time, so this needs a new transaction
            let mut txn = self.test_env.pool.begin().await.unwrap();
            db::machine::update_discovery_time(host_machine_id, &mut txn)
                .await
                .unwrap();

            txn.commit().await.unwrap();
            stop_state
        } else {
            state
        }
    }
}

/// Use this function to make a new managed host with a given number of DPUs, using site-explorer
/// to ingest it into the database. Returns a MockExploredHost that you can call more methods on
/// before finishing.
pub async fn new_mock_host(
    env: &'_ TestEnv,
    config: ManagedHostConfig,
) -> eyre::Result<MockExploredHost<'_>> {
    // Make the IB ports visible in Mock-UFM
    let mock_ib_fabric = env.ib_fabric_manager.get_mock_manager();
    for ib_guid in config.ib_guids.iter() {
        mock_ib_fabric.register_port(ib_guid.clone());
    }

    // Set BMC credentials in vault
    for bmc_mac_address in vec![config.bmc_mac_address]
        .into_iter()
        .chain(config.dpus.iter().map(|d| d.bmc_mac_address))
    {
        env.api
            .credential_provider
            .set_credentials(
                &CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                },
                &Credentials::UsernamePassword {
                    username: "root".to_string(),
                    password: "notforprod".to_string(),
                },
            )
            .await?;
    }

    let dpu_count = config.dpus.len() as u8;
    let mut mock_explored_host = MockExploredHost::new(env, config);

    // Run BMC DHCP. DPUs first...
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_bmc(dpu_index, |_, _| Ok(()))
            .await?;
    }

    // Run DHCP for DPU primary iface
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_primary_iface(dpu_index)
            .await;
    }

    // Run through site explorer iterations to get it ready.
    // NOTE: Calling `.boxed()` on each future here decreases the amount of stack space used by
    // these futures. Prior to this we were hitting stack space limits (going over 2MB in stack) in
    // unit tests. This buys us some savings so that we don't have to fiddle with adjusting the
    // default stack size.
    Ok(mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .mark_preingestion_complete()
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .discover_dhcp_host_primary_iface(|_, _| Ok(()))
        .boxed()
        .await?
        .dpu_state_controller_iterations()
        .boxed()
        .await
        .discover_machine(|_, _| Ok(()))
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .host_state_controller_iterations()
        .boxed()
        .await)
}

/// Use this function to make a new managed host with a given number of DPUs, using site-explorer
/// to ingest it into the database. Returns the ManagedHostStateSnapshot of what was created
pub async fn new_host(
    env: &TestEnv,
    config: ManagedHostConfig,
) -> eyre::Result<ManagedHostStateSnapshot> {
    new_mock_host(env, config)
        .await?
        .finish(|mock| async move {
            let machine_id = mock.discovered_machine_id().unwrap();
            Ok(db::managed_host::load_snapshot(
                &mut env.db_reader(),
                &machine_id,
                Default::default(),
            )
            .await
            .transpose()
            .unwrap()?)
        })
        .await
}

pub async fn new_host_with_machine_validation(
    env: &TestEnv,
    dpu_count: u8,
    machine_validation_result_data: Option<rpc::forge::MachineValidationResult>,
    error: Option<String>,
) -> eyre::Result<ManagedHostStateSnapshot> {
    let managed_host =
        ManagedHostConfig::with_dpus((0..dpu_count).map(|_| DpuConfig::default()).collect());
    let mut mock_explored_host = MockExploredHost::new(env, managed_host);

    // Run BMC DHCP. DPUs first...
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_bmc(dpu_index, |_, _| Ok(()))
            .await?;
    }

    // Run DHCP for DPU primary iface
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_primary_iface(dpu_index)
            .await;
    }

    mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .mark_preingestion_complete()
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .discover_dhcp_host_primary_iface(|_, _| Ok(()))
        .boxed()
        .await?
        .dpu_state_controller_iterations()
        .boxed()
        .await
        .discover_machine(|_, _| Ok(()))
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .host_state_controller_iterations_with_machine_validation(
            machine_validation_result_data,
            error,
        )
        .boxed()
        .await
        .finish(|mock| async move {
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok(db::managed_host::load_snapshot(
                &mut env.db_reader(),
                &machine_id,
                Default::default(),
            )
            .await
            .transpose()
            .unwrap()?)
        })
        .boxed()
        .await
}

pub async fn new_dpu(env: &TestEnv, config: ManagedHostConfig) -> eyre::Result<MachineId> {
    let mut mock_explored_host = MockExploredHost::new(env, config);

    mock_explored_host = mock_explored_host
        .discover_dhcp_dpu_bmc(0, |_, _| Ok(()))
        .await?;

    mock_explored_host = mock_explored_host.discover_dhcp_dpu_primary_iface(0).await;

    mock_explored_host = mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .mark_preingestion_complete()
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .dpu_state_controller_iterations()
        .boxed()
        .await;

    Ok(mock_explored_host.dpu_machine_ids[&0])
}

pub async fn new_dpu_in_network_install(
    env: &TestEnv,
    config: ManagedHostConfig,
) -> eyre::Result<TestManagedHost> {
    let mut mock_explored_host = MockExploredHost::new(env, config);

    mock_explored_host = mock_explored_host
        .discover_dhcp_dpu_bmc(0, |_, _| Ok(()))
        .await?;

    mock_explored_host = mock_explored_host.discover_dhcp_dpu_primary_iface(0).await;

    mock_explored_host = mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .mark_preingestion_complete()
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .dpu_state_controller_iterations_to_network_install()
        .boxed()
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine_id = mock_explored_host.dpu_machine_ids[&0];
    let host_machine_id = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap()
        .id;

    Ok(TestManagedHost {
        id: host_machine_id,
        dpu_ids: vec![dpu_machine_id],
        api: env.api.clone(),
    })
}

/// Creates a new power shelf for testing purposes
pub async fn new_power_shelf(
    env: &TestEnv,
    name: Option<String>,
    capacity: Option<u32>,
    voltage: Option<u32>,
    location: Option<String>,
) -> eyre::Result<PowerShelfId> {
    let mut txn = env.pool.begin().await.unwrap();

    // Generate a unique name if not provided
    let power_shelf_name = name.unwrap_or_else(|| {
        format!(
            "Test Power Shelf {}",
            &uuid::Uuid::new_v4().to_string()[..8]
        )
    });

    // Generate power shelf ID using hardware info
    let power_shelf_serial = &power_shelf_name;
    let power_shelf_vendor = "NVIDIA";
    let power_shelf_model = "PowerShelf";

    let power_shelf_id = from_hardware_info(
        power_shelf_serial,
        power_shelf_vendor,
        power_shelf_model,
        PowerShelfIdSource::ProductBoardChassisSerial,
        PowerShelfType::Rack,
    )
    .map_err(|e| eyre::eyre!("Failed to create power shelf ID: {:?}", e))?;

    // Create power shelf configuration
    let config = PowerShelfConfig {
        name: power_shelf_name,
        capacity: capacity.or(Some(100)),
        voltage: voltage.or(Some(240)),
        location: location.or(Some("US/CA/DC/San Jose/1000 N Mathilda Ave".to_string())),
    };

    // Create the power shelf
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config,
    };

    let _power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf)
        .await
        .map_err(|e| eyre::eyre!("Failed to create power shelf: {:?}", e))?;

    txn.commit().await.unwrap();

    Ok(power_shelf_id)
}

#[allow(dead_code)]
pub async fn new_power_shelfs(env: &TestEnv, count: u32) -> eyre::Result<Vec<PowerShelfId>> {
    let mut power_shelf_ids = Vec::new();
    for i in 0..count {
        power_shelf_ids.push(
            new_power_shelf(
                env,
                Some(format!("Test Power Shelf {}", i)),
                None,
                None,
                None,
            )
            .await?,
        );
    }
    Ok(power_shelf_ids)
}

pub struct TestRackDbBuilder {
    compute_trays: Vec<MachineId>,
    power_shelves: Vec<PowerShelfId>,
    // TODO: unhide this when we have machine-a-tron support for switch
    _switches: Vec<SwitchId>,
    expected_compute_trays: Vec<MacAddress>,
    expected_power_shelves: Vec<MacAddress>,
    expected_switches: Vec<MacAddress>,
    rack_id: RackId,
}

impl Default for TestRackDbBuilder {
    fn default() -> Self {
        TestRackDbBuilder {
            compute_trays: vec![],
            power_shelves: vec![],
            // TODO: unhide this when we have machine-a-tron support for switch
            _switches: vec![],
            expected_compute_trays: vec![],
            expected_power_shelves: vec![],
            expected_switches: vec![],
            rack_id: RackId::from(uuid::Uuid::new_v4()),
        }
    }
}

impl TestRackDbBuilder {
    pub fn new() -> TestRackDbBuilder {
        TestRackDbBuilder {
            ..Default::default()
        }
    }

    pub fn with_rack_id(mut self, id: RackId) -> Self {
        self.rack_id = id;
        self
    }

    /// TODO: unhide this when we have a test that prefills the discovered
    /// compute trays  
    pub fn _with_compute_trays(mut self, compute_trays: Vec<MachineId>) -> Self {
        self.compute_trays = compute_trays;
        self
    }

    /// TODO: unhide this when we have a test that prefills the discovered
    /// power shelfs
    pub fn _with_power_shelves(mut self, power_shelves: Vec<PowerShelfId>) -> Self {
        self.power_shelves = power_shelves;
        self
    }

    /// TODO: unhide this when we have a test that prefills the discovered
    /// switches
    pub fn _with_switches(mut self, switches: Vec<SwitchId>) -> Self {
        self._switches = switches;
        self
    }

    pub fn with_expected_compute_trays(mut self, expected_compute_trays: Vec<[u8; 6]>) -> Self {
        self.expected_compute_trays = expected_compute_trays
            .into_iter()
            .map(MacAddress::new)
            .collect();
        self
    }

    pub fn with_expected_power_shelves(mut self, expected_power_shelves: Vec<[u8; 6]>) -> Self {
        self.expected_power_shelves = expected_power_shelves
            .into_iter()
            .map(MacAddress::new)
            .collect();
        self
    }

    /// TODO: unhide this when we have a test that sets expected switches (presumably, but
    /// not necessarily when machine-a-tron supports switches)
    pub fn _with_expected_switches(mut self, expected_switches: Vec<[u8; 6]>) -> Self {
        self.expected_switches = expected_switches.into_iter().map(MacAddress::new).collect();
        self
    }

    pub async fn persist(&self, txn: &mut PgConnection) -> Result<RackId, DatabaseError> {
        db_rack::create(
            txn,
            self.rack_id,
            self.expected_compute_trays.clone(),
            self.expected_switches.clone(),
            self.expected_power_shelves.clone(),
        )
        .await?;

        if !self.compute_trays.is_empty() || !self.power_shelves.is_empty() {
            let cfg = RackConfig {
                compute_trays: self.compute_trays.clone(),
                power_shelves: self.power_shelves.clone(),
                expected_compute_trays: self.expected_compute_trays.clone(),
                expected_power_shelves: self.expected_power_shelves.clone(),
            };

            db_rack::update(txn, self.rack_id, &cfg).await?;
        }

        Ok(self.rack_id)
    }
}

/// Creates a new switch for testing purposes
pub async fn new_switch(
    env: &TestEnv,
    name: Option<String>,
    location: Option<String>,
) -> eyre::Result<SwitchId> {
    let mut txn = env.pool.begin().await.unwrap();

    // Generate a unique name if not provided
    let switch_name =
        name.unwrap_or_else(|| format!("Test Switch {}", &uuid::Uuid::new_v4().to_string()[..8]));

    // Generate switch ID using hardware info
    let switch_serial = &switch_name;
    let switch_vendor = "NVIDIA";
    let switch_model = "Switch";

    let switch_id = switch_from_hardware_info(
        switch_serial,
        switch_vendor,
        switch_model,
        SwitchIdSource::ProductBoardChassisSerial,
        SwitchType::NvLink,
    )
    .map_err(|e| eyre::eyre!("Failed to create switch ID: {:?}", e))?;

    // Create switch configuration.
    let config = SwitchConfig {
        name: switch_name,
        enable_nmxc: false,
        fabric_manager_config: None,
        location: location.or(Some("US/CA/DC/San Jose/1000 N Mathilda Ave".to_string())),
    };

    // Create the switch
    let new_switch = NewSwitch {
        id: switch_id,
        config,
    };

    let _switch = db_switch::create(&mut txn, &new_switch)
        .await
        .map_err(|e| eyre::eyre!("Failed to create switch: {:?}", e))?;

    txn.commit().await.unwrap();

    Ok(switch_id)
}

/// It is neccesary to start a tower_test server to simulate the kube environment and handle the DPF requests.
pub async fn new_mock_host_with_dpf(
    env: &'_ TestEnv,
    config: ManagedHostConfig,
) -> eyre::Result<ManagedHostStateSnapshot> {
    // Make the IB ports visible in Mock-UFM
    let mock_ib_fabric = env.ib_fabric_manager.get_mock_manager();
    for ib_guid in config.ib_guids.iter() {
        mock_ib_fabric.register_port(ib_guid.clone());
    }

    // Set BMC credentials in vault
    for bmc_mac_address in vec![config.bmc_mac_address]
        .into_iter()
        .chain(config.dpus.iter().map(|d| d.bmc_mac_address))
    {
        env.api
            .credential_provider
            .set_credentials(
                &CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                },
                &Credentials::UsernamePassword {
                    username: "root".to_string(),
                    password: "notforprod".to_string(),
                },
            )
            .await?;
    }

    let dpu_count = config.dpus.len() as u8;
    let mut mock_explored_host = MockExploredHost::new(env, config);

    // Run BMC DHCP. DPUs first...
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_bmc(dpu_index, |_, _| Ok(()))
            .await?;
    }

    // Run DHCP for DPU primary iface
    for dpu_index in 0..dpu_count {
        mock_explored_host = mock_explored_host
            .discover_dhcp_dpu_primary_iface(dpu_index)
            .await;
    }

    // Run through site explorer iterations to get it ready.
    // NOTE: Calling `.boxed()` on each future here decreases the amount of stack space used by
    // these futures. Prior to this we were hitting stack space limits (going over 2MB in stack) in
    // unit tests. This buys us some savings so that we don't have to fiddle with adjusting the
    // default stack size.
    mock_explored_host
        // ...Then run host BMC's DHCP
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .mark_preingestion_complete()
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .discover_dhcp_host_primary_iface(|_, _| Ok(()))
        .boxed()
        .await?
        .dpu_state_controller_iterations_with_dpf()
        .boxed()
        .await
        .discover_machine(|_, _| Ok(()))
        .boxed()
        .await?
        .run_site_explorer_iteration()
        .boxed()
        .await
        .host_state_controller_iterations()
        .boxed()
        .await
        .finish(|mock| async move {
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok(db::managed_host::load_snapshot(
                &mut env.db_reader(),
                &machine_id,
                Default::default(),
            )
            .await
            .transpose()
            .unwrap()
            .unwrap())
        })
        .boxed()
        .await
}
