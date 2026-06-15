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
use std::net::IpAddr;

use carbide_api_core::test_support::Api;
use carbide_api_core::test_support::fixture_config::{
    FixtureDefault as _, ManagedHostConfigExt as _,
};
use carbide_site_explorer::test_support::TestSiteExplorer;
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{Machine, ManagedHostState};
use model::test_support::{DpuConfig, ManagedHostConfig};

use crate::TestHarness;
use crate::network::segment::TestNetworkSegment;
use crate::rpc::forge::forge_server::Forge;
use crate::rpc::forge::{
    DhcpDiscovery, DhcpRecord, HealthReportEntry, InsertMachineHealthReportRequest,
    MachineDiscoveryResult, ManagedHostNetworkConfigRequest,
};
use crate::rpc::{DiscoveryData, DiscoveryInfo};

pub struct TestManagedHost {
    pub managed_host: ManagedHostConfig,
    pub host_bmc_ip: IpAddr,
    pub dpu_bmc_ips: Vec<(u8, IpAddr)>,
    pub host_machine_id: MachineId,
    pub dpu_machine_ids: HashMap<u8, MachineId>,
}

impl TestManagedHost {
    pub fn dpu_machine_id(&self, dpu_index: u8) -> MachineId {
        *self
            .dpu_machine_ids
            .get(&dpu_index)
            .expect("DPU machine id should exist")
    }

    pub fn dpu_bmc_ip(&self, dpu_index: u8) -> IpAddr {
        self.dpu_bmc_ips
            .iter()
            .find(|(index, _)| *index == dpu_index)
            .map(|(_, ip)| *ip)
            .expect("DPU BMC IP should exist")
    }

    pub async fn dhcp_discover_host_primary_iface(
        &self,
        api: &Api,
        segment: TestNetworkSegment,
    ) -> DhcpRecord {
        api.discover_dhcp(
            DhcpDiscovery::builder(self.managed_host.dhcp_mac_address(), segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await
        .expect("host primary interface DHCP discovery should succeed")
        .into_inner()
    }

    pub async fn discover_host_primary_iface(&mut self, api: &Api, segment: TestNetworkSegment) {
        let dhcp_record = self.dhcp_discover_host_primary_iface(api, segment).await;
        self.host_machine_id =
            discover_machine(api, &dhcp_record, HardwareInfo::from(&self.managed_host))
                .await
                .machine_id
                .expect("host discovery should return a machine id");
    }

    pub async fn dhcp_discover_dpu_oob_ifaces(
        &self,
        api: &Api,
        segment: TestNetworkSegment,
    ) -> Vec<DhcpRecord> {
        let mut dhcp_records = Vec::new();
        for dpu in &self.managed_host.dpus {
            let dhcp_record = api
                .discover_dhcp(
                    DhcpDiscovery::builder(dpu.oob_mac_address, segment.relay_address)
                        .vendor_string("SomeVendor")
                        .tonic_request(),
                )
                .await
                .expect("DPU OOB interface DHCP discovery should succeed")
                .into_inner();
            dhcp_records.push(dhcp_record);
        }
        dhcp_records
    }

    pub async fn discover_dpu_oob_ifaces(&mut self, api: &Api, segment: TestNetworkSegment) {
        let dhcp_records = self.dhcp_discover_dpu_oob_ifaces(api, segment).await;
        for (dpu_index, (dpu, dhcp_record)) in self
            .managed_host
            .dpus
            .iter()
            .zip(dhcp_records.iter())
            .enumerate()
        {
            let dpu_index = dpu_index.try_into().expect("DPU index should fit into u8");
            self.dpu_machine_ids.insert(
                dpu_index,
                discover_machine(api, dhcp_record, HardwareInfo::from(dpu))
                    .await
                    .machine_id
                    .expect("DPU discovery should return a machine id"),
            );
        }
    }

    pub async fn insert_empty_host_health_report(&self, api: &Api, source: impl Into<String>) {
        api.insert_machine_health_report(tonic::Request::new(InsertMachineHealthReportRequest {
            health_report_entry: Some(HealthReportEntry {
                report: Some(crate::rpc::health::HealthReport {
                    source: source.into(),
                    triggered_by: None,
                    observed_at: None,
                    successes: vec![],
                    alerts: vec![],
                }),
                ..Default::default()
            }),
            machine_id: Some(self.host_machine_id),
        }))
        .await
        .expect("empty host health report should be inserted");
    }

    pub async fn advance_host_state(&self, test_harness: &TestHarness, state: ManagedHostState) {
        let mut txn = test_harness.db_txn().await;
        let machine = self.host_db_machine(&mut txn).await;
        db::machine::advance(&machine, &mut txn, &state, None)
            .await
            .expect("host state should be advanced");
        txn.commit()
            .await
            .expect("database transaction should commit");
    }

    pub async fn host_db_machine(&self, txn: &mut sqlx::PgTransaction<'_>) -> Machine {
        db::machine::find_one(
            txn.as_mut(),
            &self.host_machine_id,
            MachineSearchConfig::default(),
        )
        .await
        .expect("host machine lookup should succeed")
        .expect("host machine should exist")
    }

    /// Simulate forge-dpu-agent fetching, applying, and reporting DPU network status.
    pub async fn report_dpu_network_status(&self, api: &Api) {
        for dpu_machine_id in self.dpu_machine_ids.values() {
            record_dpu_network_status(api, *dpu_machine_id).await;
        }
    }
}

pub struct TestManagedHostBuilder<'a> {
    test_harness: &'a TestHarness,
    site_explorer: &'a TestSiteExplorer,
    segment: TestNetworkSegment,
    managed_host: ManagedHostConfig,
    report_dpu_network_status: bool,
}

impl<'a> TestManagedHostBuilder<'a> {
    pub(crate) fn new(
        test_harness: &'a TestHarness,
        site_explorer: &'a TestSiteExplorer,
        segment: TestNetworkSegment,
    ) -> Self {
        Self {
            test_harness,
            site_explorer,
            segment,
            managed_host: ManagedHostConfig::default(),
            report_dpu_network_status: false,
        }
    }

    pub fn with_config(mut self, managed_host: ManagedHostConfig) -> Self {
        self.managed_host = managed_host;
        self
    }

    pub fn with_dpu_count(self, dpu_count: usize) -> Self {
        assert!(dpu_count >= 1, "need to specify at least 1 DPU");
        self.with_config(ManagedHostConfig::with_dpus(
            (0..dpu_count).map(|_| DpuConfig::default()).collect(),
        ))
    }

    /// Report DPU network status as part of `build`.
    pub fn with_dpu_network_status_reported(mut self) -> Self {
        self.report_dpu_network_status = true;
        self
    }

    pub async fn build(self) -> TestManagedHost {
        register_expected_machine(self.test_harness, &self.managed_host).await;

        let host_bmc_ip = discover_bmc(
            self.test_harness.api(),
            self.managed_host.bmc_mac_address,
            self.segment,
            "SomeVendor",
        )
        .await;
        let mut dpu_bmc_ips = Vec::new();
        for (dpu_index, dpu) in self.managed_host.dpus.iter().enumerate() {
            let dpu_index = dpu_index.try_into().expect("DPU index should fit into u8");
            let bmc_ip = discover_bmc(
                self.test_harness.api(),
                dpu.bmc_mac_address,
                self.segment,
                "NVIDIA/BF/BMC",
            )
            .await;
            dpu_bmc_ips.push((dpu_index, bmc_ip));
        }

        let results = self
            .managed_host
            .exploration_results(Some(host_bmc_ip), &dpu_bmc_ips)
            .expect("managed host exploration results should be generated");
        let dpu_machine_ids = results.dpu_machine_ids();
        self.site_explorer
            .insert_endpoints(results.into_endpoints());

        // First iteration explores the endpoints. Preingestion then completes
        // outside site-explorer, and the second iteration creates the managed host.
        self.site_explorer
            .run_single_iteration()
            .await
            .expect("first site explorer iteration should succeed");

        let mut txn = self.test_harness.db_txn().await;
        db::explored_endpoints::set_preingestion_complete(host_bmc_ip, &mut txn)
            .await
            .expect("host endpoint preingestion should be marked complete");
        for (_, dpu_bmc_ip) in &dpu_bmc_ips {
            db::explored_endpoints::set_preingestion_complete(*dpu_bmc_ip, &mut txn)
                .await
                .expect("DPU endpoint preingestion should be marked complete");
        }
        txn.commit()
            .await
            .expect("database transaction should commit");

        self.site_explorer
            .run_single_iteration()
            .await
            .expect("second site explorer iteration should succeed");

        let mut txn = self.test_harness.db_txn().await;
        let host_machine_id = db::machine::find_id_by_bmc_ip(&mut txn, &host_bmc_ip)
            .await
            .expect("host machine lookup by BMC IP should succeed")
            .expect("host machine should have been created for the explored BMC");
        txn.commit()
            .await
            .expect("database transaction should commit");

        let managed_host = TestManagedHost {
            managed_host: self.managed_host,
            host_bmc_ip,
            dpu_bmc_ips,
            host_machine_id,
            dpu_machine_ids,
        };

        if self.report_dpu_network_status {
            managed_host
                .report_dpu_network_status(self.test_harness.api())
                .await;
        }

        managed_host
    }
}

async fn register_expected_machine(test_harness: &TestHarness, managed_host: &ManagedHostConfig) {
    let mut txn = test_harness.db_txn().await;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: managed_host.bmc_mac_address,
            data: managed_host
                .expected_machine_data
                .clone()
                .unwrap_or_else(|| ExpectedMachineData {
                    serial_number: managed_host.serial.clone(),
                    ..Default::default()
                }),
        },
    )
    .await
    .expect("expected machine should be created");
    txn.commit()
        .await
        .expect("database transaction should commit");
}

async fn discover_bmc(
    api: &Api,
    mac_address: MacAddress,
    segment: TestNetworkSegment,
    vendor_string: &str,
) -> IpAddr {
    api.discover_dhcp(
        DhcpDiscovery::builder(mac_address, segment.relay_address)
            .vendor_string(vendor_string)
            .tonic_request(),
    )
    .await
    .expect("BMC DHCP discovery should succeed")
    .into_inner()
    .address
    .parse()
    .expect("DHCP response address should be an IP address")
}

async fn discover_machine(
    api: &Api,
    dhcp_record: &DhcpRecord,
    hardware_info: HardwareInfo,
) -> MachineDiscoveryResult {
    api.discover_machine(tonic::Request::new(
        crate::rpc::forge::MachineDiscoveryInfo {
            machine_interface_id: Some(
                *dhcp_record
                    .machine_interface_id
                    .as_ref()
                    .expect("DHCP record should include a machine interface id"),
            ),
            create_machine: true,
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(hardware_info)
                    .expect("hardware info should convert to discovery info"),
            )),
            ..Default::default()
        },
    ))
    .await
    .expect("machine discovery should succeed")
    .into_inner()
}

async fn record_dpu_network_status(api: &Api, dpu_machine_id: MachineId) {
    let network_config = api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .expect("managed host network config should be available")
        .into_inner();

    let instance_network_config_version =
        if network_config.instance_network_config_version.is_empty() {
            None
        } else {
            Some(network_config.instance_network_config_version.clone())
        };
    let instance_config_version = api
        .find_instance_by_machine_id(tonic::Request::new(dpu_machine_id))
        .await
        .expect("instance lookup by machine id should succeed")
        .into_inner()
        .instances
        .pop()
        .map(|instance| {
            if !network_config.use_admin_network {
                assert_eq!(
                    instance_network_config_version
                        .as_ref()
                        .expect("instance network config version should be set")
                        .as_str(),
                    instance.network_config_version,
                    "Different network config versions reported via FindInstanceByMachineId and GetManagedHostNetworkConfig"
                );
            }
            instance.config_version
        });

    let interfaces = if network_config.use_admin_network {
        let iface = network_config
            .admin_interface
            .as_ref()
            .expect("admin interface should be available when using admin network");
        vec![crate::rpc::forge::InstanceInterfaceStatusObservation {
            function_type: iface.function_type,
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![iface.ip.clone()],
            prefixes: vec![iface.interface_prefix.clone()],
            gateways: vec![iface.gateway.clone()],
            network_security_group: None,
            internal_uuid: iface.internal_uuid.clone(),
        }]
    } else {
        network_config
            .tenant_interfaces
            .iter()
            .map(
                |iface| crate::rpc::forge::InstanceInterfaceStatusObservation {
                    function_type: iface.function_type,
                    virtual_function_id: iface.virtual_function_id,
                    mac_address: None,
                    addresses: vec![iface.ip.clone()],
                    prefixes: vec![iface.interface_prefix.clone()],
                    gateways: vec![iface.gateway.clone()],
                    network_security_group: None,
                    internal_uuid: iface.internal_uuid.clone(),
                },
            )
            .collect()
    };

    let dpu_extension_services = network_config
        .dpu_extension_services
        .iter()
        .map(
            |extension_service| crate::rpc::forge::DpuExtensionServiceStatusObservation {
                service_id: extension_service.service_id.clone(),
                service_type: extension_service.service_type,
                service_name: "".to_string(),
                version: extension_service.version.to_string(),
                state: crate::rpc::forge::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceRunning
                    as i32,
                components: vec![],
                message: "".to_string(),
                removed: extension_service.removed.clone(),
            },
        )
        .collect();

    api.record_dpu_network_status(tonic::Request::new(crate::rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id),
        dpu_agent_version: Some("test-dpu-agent-version".to_string()),
        observed_at: None,
        dpu_health: Some(crate::rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: vec![],
        }),
        network_config_version: Some(network_config.managed_host_config_version.clone()),
        instance_id: network_config.instance_id,
        instance_config_version,
        instance_network_config_version,
        interfaces,
        network_config_error: None,
        client_certificate_expiry_unix_epoch_secs: None,
        fabric_interfaces: vec![],
        last_dhcp_requests: vec![],
        dpu_extension_service_version: network_config
            .instance
            .map(|instance| instance.dpu_extension_service_version),
        dpu_extension_services,
    }))
    .await
    .expect("DPU network status should be recorded");
}
