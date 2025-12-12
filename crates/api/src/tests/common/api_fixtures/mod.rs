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

//! Contains fixtures that use the Carbide API for setting up

use std::collections::HashMap;
use std::default::Default;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use carbide_dpf::KubeImpl;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use chrono::{DateTime, Duration, Utc};
use db::instance_type::create as create_instance_type;
use db::network_security_group::create as create_network_security_group;
use db::work_lock_manager;
use dpu::DpuConfig;
use forge_secrets::credentials::{
    CredentialKey, CredentialProvider, CredentialType, Credentials, TestCredentialProvider,
};
use futures::FutureExt as _;
use health_report::{HealthReport, OverrideMode};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use measured_boot::pcr::PcrRegisterValue;
use model::attestation::spdm::Verifier;
use model::firmware::{Firmware, FirmwareComponent, FirmwareComponentType, FirmwareEntry};
use model::hardware_info::TpmEkCertificate;
use model::instance_type::InstanceTypeMachineCapabilityFilter;
use model::machine::capabilities::MachineCapabilityType;
use model::machine::{
    FailureDetails, HostHealthConfig, Machine, MachineLastRebootRequested, MachineValidatingState,
    ManagedHostState, ValidationState,
};
use model::metadata::Metadata;
use model::network_security_group;
use model::resource_pool::common::CommonPools;
use model::resource_pool::{self};
use model::tenant::TenantOrganizationId;
use nras::{
    DeviceAttestationInfo, NrasError, ProcessedAttestationOutcome, RawAttestationOutcome,
    VerifierClient,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use regex::Regex;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    HealthReportOverride, InsertHealthReportOverrideRequest, RemoveHealthReportOverrideRequest,
    VpcVirtualizationType,
};
use rpc_instance::RpcInstance;
use site_explorer::new_host_with_machine_validation;
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;
use tokio::sync::Mutex;
use tonic::Request;
use tracing_subscriber::EnvFilter;

use crate::api::Api;
use crate::cfg::file::{
    BomValidationConfig, CarbideConfig, DpaConfig, DpaInterfaceStateControllerConfig,
    DpuConfig as InitialDpuConfig, FirmwareGlobal, IBFabricConfig, IbFabricDefinition,
    IbPartitionStateControllerConfig, ListenMode, MachineStateControllerConfig, MachineUpdater,
    MachineValidationConfig, MeasuredBootMetricsCollectorConfig, NetworkSecurityGroupConfig,
    NetworkSegmentStateControllerConfig, NvLinkConfig, PowerManagerOptions,
    PowerShelfStateControllerConfig, RackStateControllerConfig, SiteExplorerConfig, SpdmConfig,
    SpdmStateControllerConfig, StateControllerConfig, SwitchStateControllerConfig, VmaasConfig,
    VpcPeeringPolicy, default_max_find_by_ids,
};
use crate::ethernet_virtualization::{EthVirtData, SiteFabricPrefixList};
use crate::ib::{self, IBFabricManagerImpl, IBFabricManagerType};
use crate::ib_fabric_monitor::IbFabricMonitor;
use crate::ipmitool::IPMIToolTestImpl;
use crate::logging::level_filter::ActiveLevel;
use crate::logging::log_limiter::LogLimiter;
use crate::nvl_partition_monitor::NvlPartitionMonitor;
use crate::nvlink::NmxmClientPool;
use crate::nvlink::test_support::NmxmSimClient;
use crate::rack::rms_client::test_support::RmsSim;
use crate::redfish::test_support::RedfishSim;
use crate::scout_stream;
use crate::site_explorer::{BmcEndpointExplorer, SiteExplorer};
use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::controller::{Enqueuer, StateController};
use crate::state_controller::ib_partition::handler::IBPartitionStateHandler;
use crate::state_controller::ib_partition::io::IBPartitionStateControllerIO;
use crate::state_controller::machine::handler::{
    DpfConfig, MachineStateHandler, MachineStateHandlerBuilder, PowerOptionConfig,
    ReachabilityParams,
};
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::state_controller::network_segment::handler::NetworkSegmentStateHandler;
use crate::state_controller::network_segment::io::NetworkSegmentStateControllerIO;
use crate::state_controller::power_shelf::handler::PowerShelfStateHandler;
use crate::state_controller::power_shelf::io::PowerShelfStateControllerIO;
use crate::state_controller::spdm::handler::SpdmAttestationStateHandler;
use crate::state_controller::spdm::io::SpdmStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcomeWithTransaction,
};
use crate::state_controller::switch::handler::SwitchStateHandler;
use crate::state_controller::switch::io::SwitchStateControllerIO;
use crate::tests::common::api_fixtures::endpoint_explorer::MockEndpointExplorer;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY, create_admin_network_segment,
    create_tenant_network_segment, create_underlay_network_segment,
};
use crate::tests::common::rpc_builder::VpcCreationRequest;
use crate::tests::common::test_certificates::TestCertificateProvider;
use crate::tests::common::test_meter::TestMeter;

pub mod dpu;
pub mod endpoint_explorer;
pub mod host;
pub mod ib_partition;
pub mod instance;
pub mod managed_host;
pub mod network_segment;
pub mod nvl_logical_partition;
pub mod rpc_instance;
pub mod site_explorer;
pub mod tenant;
pub mod test_machine;
pub mod test_managed_host;
pub mod tpm_attestation;
pub mod vpc;

pub type TestMachine = test_machine::TestMachine;
pub type TestManagedHost = test_managed_host::TestManagedHost;

/// The datacenter-level DHCP relay that is assumed for all DPU discovery
///
/// For integration testing this must match a prefix defined in fixtures/create_network_segment.sql
/// In production the relay IP is a MetalLB VIP so isn't in a network segment.
pub const FIXTURE_DHCP_RELAY_ADDRESS: &str = "192.0.2.1";

// The site fabric prefixes list that the tests run with. Double check against
// the test logic before changing it, as at least one test relies on this list
// _excluding_ certain address space.
lazy_static! {
    pub static ref TEST_SITE_PREFIXES: Vec<IpNetwork> = vec![
        IpNetwork::new(
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[2].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[2].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[3].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[3].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[4].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[4].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[5].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[5].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[6].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[6].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[7].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[7].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[8].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[8].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[9].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[9].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[10].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[10].prefix(),
        )
        .unwrap(),
    ];
}

#[derive(Clone, Debug)]
pub struct TestDpfKubeClient {}

#[async_trait::async_trait]
impl KubeImpl for TestDpfKubeClient {
    async fn get_kube_client(&self) -> Result<kube::Client, carbide_dpf::DpfError> {
        let (service, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(service, "default");
        Ok(client)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestEnvOverrides {
    pub allow_zero_dpu_hosts: Option<bool>,
    pub site_prefixes: Option<Vec<IpNetwork>>,
    pub config: Option<CarbideConfig>,
    pub create_network_segments: Option<bool>,
    pub dpu_agent_version_staleness_threshold: Option<chrono::Duration>,
    pub prevent_allocations_on_stale_dpu_agent_version: Option<bool>,
    pub network_segments_drain_period: Option<chrono::Duration>,
    pub power_manager_enabled: Option<bool>,
    pub dpf_config: Option<DpfConfig>,
    pub nmxm_default_partition: Option<bool>,
}

impl TestEnvOverrides {
    pub fn with_config(config: CarbideConfig) -> Self {
        Self {
            config: Some(config),
            ..Default::default()
        }
    }

    pub fn with_dpf_config(mut self, dpf_config: DpfConfig) -> Self {
        self.dpf_config = Some(dpf_config);
        self
    }

    pub fn no_network_segments() -> Self {
        Self {
            create_network_segments: Some(false),
            ..Default::default()
        }
    }

    pub fn enable_power_manager(mut self) -> Self {
        self.power_manager_enabled = Some(true);
        self
    }
}

pub struct TestEnv {
    pub api: Arc<Api>,
    pub config: Arc<CarbideConfig>,
    pub common_pools: Arc<CommonPools>,
    pub pool: PgPool,
    pub redfish_sim: Arc<RedfishSim>,
    pub ib_fabric_monitor: Arc<IbFabricMonitor>,
    pub ib_fabric_manager: Arc<IBFabricManagerImpl>,
    pub ipmi_tool: Arc<IPMIToolTestImpl>,
    machine_state_controller: Arc<Mutex<StateController<MachineStateControllerIO>>>,
    spdm_state_controller: Arc<Mutex<StateController<SpdmStateControllerIO>>>,
    pub machine_state_handler: SwapHandler<MachineStateHandler>,
    network_segment_controller: Arc<Mutex<StateController<NetworkSegmentStateControllerIO>>>,
    ib_partition_controller: Arc<Mutex<StateController<IBPartitionStateControllerIO>>>,
    #[allow(dead_code)]
    power_shelf_controller: Arc<Mutex<StateController<PowerShelfStateControllerIO>>>,
    #[allow(dead_code)]
    switch_controller: Arc<Mutex<StateController<SwitchStateControllerIO>>>,
    pub reachability_params: ReachabilityParams,
    pub test_meter: TestMeter,
    pub attestation_enabled: bool,
    pub site_explorer: SiteExplorer,
    pub nmxm_sim: Arc<dyn NmxmClientPool>,
    pub endpoint_explorer: MockEndpointExplorer,
    pub admin_segment: Option<NetworkSegmentId>,
    pub underlay_segment: Option<NetworkSegmentId>,
    pub domain: uuid::Uuid,
    pub nvl_partition_monitor: Arc<Mutex<NvlPartitionMonitor>>,
    pub test_credential_provider: Arc<TestCredentialProvider>,
    pub rms_sim: Arc<RmsSim>,
}

impl TestEnv {
    /// Creates an instance of CommonStateHandlerServices that are suitable for this
    /// test environment
    pub fn state_handler_services(&self) -> CommonStateHandlerServices {
        CommonStateHandlerServices {
            db_pool: self.pool.clone(),
            redfish_client_pool: self.redfish_sim.clone(),
            ib_fabric_manager: self.ib_fabric_manager.clone(),
            ib_pools: self.common_pools.infiniband.clone(),
            ipmi_tool: self.ipmi_tool.clone(),
            site_config: self.config.clone(),
            dpa_info: None,
            rms_client: self.rms_sim.as_rms_client(),
        }
    }

    /// Generates a config for Host+DPU pair
    pub fn managed_host_config(&self) -> ManagedHostConfig {
        ManagedHostConfig::default()
    }

    /// Create database transaction for tests.
    pub async fn db_txn(&self) -> sqlx::Transaction<'_, sqlx::Postgres> {
        self.pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool")
    }

    fn fill_machine_information(
        &self,
        state: &ManagedHostState,
        machine: &Machine,
    ) -> ManagedHostState {
        //This block is to fill data that is populated within statemachine
        match state.clone() {
            ManagedHostState::DpuDiscoveringState { .. } => state.clone(),
            ManagedHostState::DPUInit { .. } => state.clone(),
            ManagedHostState::HostInit { machine_state } => {
                let mc = match machine_state {
                    model::machine::MachineState::Init => machine_state,
                    model::machine::MachineState::WaitingForPlatformConfiguration => machine_state,
                    model::machine::MachineState::PollingBiosSetup => machine_state,
                    model::machine::MachineState::SetBootOrder { .. } => machine_state,
                    model::machine::MachineState::UefiSetup { .. } => machine_state,
                    model::machine::MachineState::WaitingForDiscovery => machine_state,
                    model::machine::MachineState::Discovered { .. } => machine_state,
                    model::machine::MachineState::WaitingForLockdown { .. } => machine_state,
                    model::machine::MachineState::Measuring { .. } => machine_state,

                    model::machine::MachineState::EnableIpmiOverLan => machine_state,
                };
                ManagedHostState::HostInit { machine_state: mc }
            }
            ManagedHostState::Ready => state.clone(),
            ManagedHostState::Assigned { .. } => state.clone(),
            ManagedHostState::WaitingForCleanup { .. } => state.clone(),
            ManagedHostState::Created => state.clone(),
            ManagedHostState::ForceDeletion => state.clone(),
            ManagedHostState::Failed {
                details,
                machine_id,
                retry_count,
            } => ManagedHostState::Failed {
                details: FailureDetails {
                    cause: details.cause,
                    failed_at: machine.failure_details.failed_at,
                    source: details.source,
                },
                machine_id,
                retry_count,
            },
            ManagedHostState::DPUReprovision { .. } => state.clone(),
            ManagedHostState::Measuring { .. } => state.clone(),
            ManagedHostState::PostAssignedMeasuring { .. } => state.clone(),
            ManagedHostState::HostReprovision { .. } => state.clone(),
            ManagedHostState::BomValidating { .. } => state.clone(),
            ManagedHostState::Validation { validation_state } => match validation_state {
                ValidationState::MachineValidation { machine_validation } => {
                    match machine_validation {
                        MachineValidatingState::MachineValidating {
                            context,
                            id: _,
                            completed,
                            total,
                            is_enabled,
                        } => {
                            let mut id =
                                machine.discovery_machine_validation_id.unwrap_or_default();
                            if context == "Cleanup" {
                                id = machine.cleanup_machine_validation_id.unwrap_or_default();
                            } else if context == "OnDemand" {
                                id = machine.on_demand_machine_validation_id.unwrap_or_default();
                            }
                            model::machine::ManagedHostState::Validation {
                                validation_state: ValidationState::MachineValidation {
                                    machine_validation: MachineValidatingState::MachineValidating {
                                        context,
                                        id,
                                        completed,
                                        total,
                                        is_enabled,
                                    },
                                },
                            }
                        }
                        MachineValidatingState::RebootHost { .. } => state.clone(),
                    }
                }
            },
        }
    }

    pub async fn run_machine_state_controller_iteration_until_state_matches(
        &self,
        host_machine_id: &MachineId,
        max_iterations: u32,
        expected_state: ManagedHostState,
    ) {
        self.run_machine_state_controller_iteration_until_state_condition(
            host_machine_id,
            max_iterations,
            |machine| {
                let fixed_expected_state = self.fill_machine_information(&expected_state, machine);
                machine.current_state() == &fixed_expected_state
            },
        )
        .await;
    }

    /// Runs iterations of the machine state controller handler with the services
    /// in this test environment until the condition is met.  using a callback function
    /// allows the caller to use "matches!" to compare patterns instead of concrete values.
    pub async fn run_machine_state_controller_iteration_until_state_condition(
        &self,
        host_machine_id: &MachineId,
        max_iterations: u32,
        state_check: impl Fn(&Machine) -> bool,
    ) -> ManagedHostState {
        for _ in 0..max_iterations {
            self.machine_state_controller
                .lock()
                .await
                .run_single_iteration()
                .boxed()
                .await;

            let mut txn: sqlx::Transaction<'static, sqlx::Postgres> =
                self.pool.begin().await.unwrap();
            let machine = db::machine::find_one(
                &mut txn,
                host_machine_id,
                model::machine::machine_search_config::MachineSearchConfig::default(),
            )
            .await
            .unwrap()
            .unwrap();

            if state_check(&machine) {
                return machine.state.value;
            }
        }
        let mut txn = self.pool.begin().await.unwrap();
        let machine = db::machine::find_one(
            &mut txn,
            host_machine_id,
            model::machine::machine_search_config::MachineSearchConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();
        panic!(
            "Expected Machine state condition not hit after {max_iterations} iterations; state is {:?}",
            machine.current_state()
        );
    }

    /// Runs one iteration of the machine state controller handler
    //// with the services in this test environment
    pub async fn run_machine_state_controller_iteration(&self) {
        self.machine_state_controller
            .lock()
            .await
            .run_single_iteration()
            .boxed()
            .await;
    }

    /// Runs one iteration of the network state controller handler with the services
    /// in this test environment
    pub async fn run_network_segment_controller_iteration(&self) {
        self.network_segment_controller
            .lock()
            .await
            .run_single_iteration()
            .boxed()
            .await;
    }

    /// Runs one iteration of the SPDM state controller handler with the services
    /// in this test environment
    pub async fn run_spdm_controller_iteration(&self) {
        self.spdm_state_controller
            .lock()
            .await
            .run_single_iteration()
            .boxed()
            .await;
    }

    /// Runs one iteration of the SPDM state controller handler with the services
    /// in this test environment
    /// No requeuing of tasks is allowed
    pub async fn run_spdm_controller_iteration_no_requeue(&self) {
        self.spdm_state_controller
            .lock()
            .await
            .run_single_iteration_ext(false)
            .boxed()
            .await;
    }

    /// Runs one iteration of the IB partition state controller handler with the services
    /// in this test environment
    pub async fn run_ib_partition_controller_iteration(&self) {
        self.ib_partition_controller
            .lock()
            .await
            .run_single_iteration()
            .boxed()
            .await;
    }

    /// Runs one iteration of the power shelf state controller handler with the services
    /// in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    #[allow(dead_code)]
    pub async fn run_power_shelf_controller_iteration(&self) {
        self.power_shelf_controller
            .lock()
            .await
            .run_single_iteration()
            .await;
    }

    /// Runs one iteration of the switch state controller handler with the services
    /// in this test environment
    #[allow(clippy::await_holding_refcell_ref)]
    #[allow(dead_code)]
    pub async fn run_switch_controller_iteration(&self) {
        self.switch_controller
            .lock()
            .await
            .run_single_iteration()
            .await;
    }

    /// Runs power shelf controller iterations until a condition is met
    #[allow(dead_code)]
    pub async fn run_power_shelf_controller_iteration_until_condition(
        &self,
        max_iterations: u32,
        condition: impl Fn() -> bool,
    ) {
        for _ in 0..max_iterations {
            self.run_power_shelf_controller_iteration().await;
            if condition() {
                return;
            }
        }
        panic!(
            "Power shelf controller condition not met after {} iterations",
            max_iterations
        );
    }

    /// Runs switch controller iterations until a condition is met
    #[allow(dead_code)]
    pub async fn run_switch_controller_iteration_until_condition(
        &self,
        max_iterations: u32,
        condition: impl Fn() -> bool,
    ) {
        for _ in 0..max_iterations {
            self.run_switch_controller_iteration().await;
            if condition() {
                return;
            }
        }
        panic!(
            "Switch controller condition not met after {} iterations",
            max_iterations
        );
    }

    pub async fn run_site_explorer_iteration(&self) {
        self.site_explorer
            .run_single_iteration()
            .boxed()
            .await
            .unwrap();
    }

    pub async fn run_ib_fabric_monitor_iteration(&self) {
        let _num_changes = self
            .ib_fabric_monitor
            .run_single_iteration()
            .boxed()
            .await
            .unwrap();
    }

    pub async fn override_machine_state_controller_handler(&self, handler: MachineStateHandler) {
        *self.machine_state_handler.inner.lock().await = handler;
    }

    // Returns all machines using FindMachinesByIds call.
    pub async fn find_machine(
        &self,
        id: carbide_uuid::machine::MachineId,
    ) -> Vec<rpc::forge::Machine> {
        self.api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![id],
                include_history: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .machines
    }

    // Returns all instances using FindInstancesByIds call.
    pub async fn find_instances(&self, ids: Vec<InstanceId>) -> rpc::forge::InstanceList {
        self.api
            .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
                instance_ids: ids,
            }))
            .await
            .unwrap()
            .into_inner()
    }

    pub async fn one_instance(&self, id: InstanceId) -> RpcInstance {
        let mut result = self
            .api
            .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
                instance_ids: vec![id],
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.instances.len(), 1);
        RpcInstance::new(result.instances.remove(0))
    }

    pub async fn create_vpc_and_tenant_segment_with_vpc_details(
        &self,
        vpc_details: rpc::forge::VpcCreationRequest,
    ) -> NetworkSegmentId {
        let vpc = self
            .api
            .create_vpc(tonic::Request::new(vpc_details))
            .await
            .unwrap()
            .into_inner();

        let tenant_network_id = create_tenant_network_segment(
            &self.api,
            vpc.id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
            "TENANT",
            true,
        )
        .await;

        // Get the tenant segment into ready state
        self.run_network_segment_controller_iteration().await;
        self.run_network_segment_controller_iteration().await;

        tenant_network_id
    }

    pub async fn create_vpc_and_tenant_segments_with_vpc_details(
        &self,
        vpc_details: rpc::forge::VpcCreationRequest,
        segment_count: usize,
    ) -> Vec<NetworkSegmentId> {
        let vpc = self
            .api
            .create_vpc(tonic::Request::new(vpc_details))
            .await
            .unwrap()
            .into_inner();

        let mut segment_ids = Vec::default();
        for segment_index in 0..segment_count {
            segment_ids.push(
                create_tenant_network_segment(
                    &self.api,
                    vpc.id,
                    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[segment_index],
                    "TENANT",
                    true,
                )
                .await,
            );

            // Get the tenant segment into ready state
            self.run_network_segment_controller_iteration().await;
            self.run_network_segment_controller_iteration().await;
        }
        segment_ids
    }

    pub async fn create_vpc_and_peer_vpc_with_tenant_segments(
        &self,
        vtype1: VpcVirtualizationType,
        vtype2: VpcVirtualizationType,
    ) -> (
        Option<VpcId>,
        Option<u32>,
        NetworkSegmentId,
        Option<VpcId>,
        Option<u32>,
        NetworkSegmentId,
    ) {
        let vpc_details =
            VpcCreationRequest::builder("test vpc", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .network_virtualization_type(vtype1)
                .tonic_request();

        let vpc = self.api.create_vpc(vpc_details).await.unwrap().into_inner();

        let tenant_network_id = create_tenant_network_segment(
            &self.api,
            vpc.id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
            "TENANT1",
            true,
        )
        .await;

        // Get the tenant segment into ready state
        self.run_network_segment_controller_iteration().await;
        self.run_network_segment_controller_iteration().await;

        let peer_vpc_details =
            VpcCreationRequest::builder("test peer vpc", "e65a9d69-39d2-4872-a53e-e5cb87c84e75")
                .network_virtualization_type(vtype2)
                .tonic_request();

        let peer_vpc = self
            .api
            .create_vpc(peer_vpc_details)
            .await
            .unwrap()
            .into_inner();

        let peer_tenant_network_id = create_tenant_network_segment(
            &self.api,
            peer_vpc.id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
            "TENANT2",
            true,
        )
        .await;

        // Get the tenant segment into ready state
        self.run_network_segment_controller_iteration().await;
        self.run_network_segment_controller_iteration().await;

        (
            vpc.id,
            vpc.vni,
            tenant_network_id,
            peer_vpc.id,
            peer_vpc.vni,
            peer_tenant_network_id,
        )
    }

    pub async fn create_vpc_and_tenant_segment(&self) -> NetworkSegmentId {
        self.create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93").rpc(),
        )
        .await
    }

    pub async fn create_vpc_and_tenant_segments(
        &self,
        segment_count: usize,
    ) -> Vec<NetworkSegmentId> {
        self.create_vpc_and_tenant_segments_with_vpc_details(
            VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93").rpc(),
            segment_count,
        )
        .await
    }

    pub async fn create_vpc_and_dual_tenant_segment(&self) -> (NetworkSegmentId, NetworkSegmentId) {
        let vpc = self
            .api
            .create_vpc(
                VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner();

        let tenant_network_id_1 = create_tenant_network_segment(
            &self.api,
            vpc.id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
            "TENANT",
            true,
        )
        .await;
        self.run_network_segment_controller_iteration().await;
        self.run_network_segment_controller_iteration().await;

        let tenant_network_id_2 = create_tenant_network_segment(
            &self.api,
            vpc.id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
            "TENANT2",
            false,
        )
        .await;
        self.run_network_segment_controller_iteration().await;
        self.run_network_segment_controller_iteration().await;

        (tenant_network_id_1, tenant_network_id_2)
    }

    pub async fn run_nvl_partition_monitor_iteration(&self) {
        self.nvl_partition_monitor
            .lock()
            .await
            .run_single_iteration()
            .boxed()
            .await
            .unwrap();
    }
}

fn dpu_fw_example() -> HashMap<String, Firmware> {
    HashMap::from([(
        "bluefield3".to_string(),
        Firmware {
            vendor: bmc_vendor::BMCVendor::Nvidia,
            model: "BlueField 3 SmartNIC Main Card".to_string(),
            ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
            explicit_start_needed: false,
            components: HashMap::from([
                (
                    FirmwareComponentType::Bmc,
                    FirmwareComponent {
                        current_version_reported_as: Some(Regex::new("BMC_Firmware").unwrap()),
                        preingest_upgrade_when_below: None,
                        known_firmware: vec![FirmwareEntry::standard("BF-24.10-17")],
                    },
                ),
                (
                    FirmwareComponentType::Cec,
                    FirmwareComponent {
                        current_version_reported_as: Some(Regex::new("Bluefield_FW_ERoT").unwrap()),
                        preingest_upgrade_when_below: None,
                        known_firmware: vec![FirmwareEntry::standard("00.02.0180.0000")],
                    },
                ),
                (
                    FirmwareComponentType::Nic,
                    FirmwareComponent {
                        current_version_reported_as: Some(Regex::new("DPU_NIC").unwrap()),
                        preingest_upgrade_when_below: None,
                        known_firmware: vec![FirmwareEntry::standard("32.39.2048")],
                    },
                ),
            ]),
        },
    )])
}

fn host_firmware_example() -> HashMap<String, Firmware> {
    HashMap::from([
        (
            "1".to_string(),
            Firmware {
                vendor: bmc_vendor::BMCVendor::Dell,
                model: "PowerEdge R750".to_string(),
                explicit_start_needed: false,
                components: HashMap::from([
                    (
                        FirmwareComponentType::Bmc,
                        FirmwareComponent {
                            current_version_reported_as: Some(
                                Regex::new("^Installed-.*__iDRAC.").unwrap(),
                            ),
                            preingest_upgrade_when_below: Some("5".to_string()),
                            known_firmware: vec![
                                FirmwareEntry::standard_notdefault("6.1"),
                                FirmwareEntry::standard_multiple_filenames("6.00.30.00"),
                                FirmwareEntry::standard_notdefault("5"),
                            ],
                        },
                    ),
                    (
                        FirmwareComponentType::Uefi,
                        FirmwareComponent {
                            current_version_reported_as: Some(
                                Regex::new("^Current-.*__BIOS.Setup.").unwrap(),
                            ),
                            preingest_upgrade_when_below: Some("1.13.2".to_string()),
                            known_firmware: vec![FirmwareEntry::standard("1.13.2")],
                        },
                    ),
                ]),
                ordering: vec![FirmwareComponentType::Uefi, FirmwareComponentType::Bmc],
            },
        ),
        (
            "2".to_string(),
            Firmware {
                vendor: bmc_vendor::BMCVendor::Dell,
                model: "Powercycle Test".to_string(),
                explicit_start_needed: false,
                components: HashMap::from([(
                    FirmwareComponentType::Uefi,
                    FirmwareComponent {
                        current_version_reported_as: Some(
                            Regex::new("^Current-.*__BIOS.Setup.").unwrap(),
                        ),
                        preingest_upgrade_when_below: Some("1.13.2".to_string()),
                        known_firmware: vec![FirmwareEntry::standard_powerdrains("1.13.2", 1002)],
                    },
                )]),
                ordering: vec![FirmwareComponentType::Uefi, FirmwareComponentType::Bmc],
            },
        ),
    ])
}

pub fn get_config() -> CarbideConfig {
    CarbideConfig {
        site_global_vpc_vni: None,
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1079),
        metrics_endpoint: None,
        alt_metric_prefix: None,
        database_url: "pgsql:://localhost".to_string(),
        max_database_connections: 1000,
        asn: 0,
        datacenter_asn: 0,
        dhcp_servers: vec![],
        route_servers: vec![],
        enable_route_servers: false,
        deny_prefixes: vec![],
        site_fabric_prefixes: vec![],
        anycast_site_prefixes: vec![],
        common_tenant_host_asn: None,
        vpc_isolation_behavior: <_ as Default>::default(),
        tls: Some(crate::cfg::file::TlsConfig {
            root_cafile_path: "Not a real path".to_string(),
            identity_pemfile_path: "Not a real pemfile".to_string(),
            identity_keyfile_path: "Not a real keyfile".to_string(),
            admin_root_cafile_path: "Not a real cafile".to_string(),
        }),
        auth: None,
        pools: None,
        networks: None,
        dpu_ipmi_tool_impl: None,
        dpu_ipmi_reboot_attempts: Some(0),
        initial_domain_name: Some("test.com".to_string()),
        sitename: Some("testsite".to_string()),
        initial_dpu_agent_upgrade_policy: None,
        max_concurrent_machine_updates: None,
        machine_update_run_interval: Some(1),
        site_explorer: SiteExplorerConfig {
            enabled: false,
            run_interval: std::time::Duration::from_secs(0),
            concurrent_explorations: 0,
            explorations_per_run: 0,
            create_machines: Arc::new(false.into()),
            allocate_secondary_vtep_ip: true,
            ..Default::default()
        },
        nvue_enabled: true,
        vpc_peering_policy: Some(VpcPeeringPolicy::Exclusive),
        vpc_peering_policy_on_existing: None,
        attestation_enabled: false,
        tpm_required: true,
        ib_config: None,
        ib_fabrics: [(
            "default".to_string(),
            IbFabricDefinition {
                // The actual IP is not used and thereby does not matter
                endpoints: vec!["https://127.0.0.1:443".to_string()],
                pkeys: vec![resource_pool::Range {
                    start: "1".to_string(),
                    end: "100".to_string(),
                }],
            },
        )]
        .into_iter()
        .collect(),
        machine_state_controller: MachineStateControllerConfig {
            dpu_wait_time: Duration::seconds(1),
            power_down_wait: Duration::seconds(1),
            failure_retry_time: Duration::seconds(1),
            dpu_up_threshold: Duration::weeks(52),
            controller: StateControllerConfig::default(),
            scout_reporting_timeout: Duration::weeks(52),
        },
        network_segment_state_controller: NetworkSegmentStateControllerConfig {
            network_segment_drain_time: Duration::seconds(2),
            controller: StateControllerConfig::default(),
        },
        ib_partition_state_controller: IbPartitionStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        dpa_interface_state_controller: DpaInterfaceStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        power_shelf_state_controller: PowerShelfStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        rack_state_controller: RackStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        switch_state_controller: SwitchStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        dpu_config: InitialDpuConfig {
            dpu_nic_firmware_initial_update_enabled: true,
            dpu_nic_firmware_reprovision_update_enabled: true,
            dpu_models: dpu_fw_example(),
            dpu_nic_firmware_update_versions: vec!["24.42.1000".to_string()],
            dpu_enable_secure_boot: true,
        },
        host_models: host_firmware_example(),
        firmware_global: FirmwareGlobal::test_default(),
        machine_updater: MachineUpdater {
            instance_autoreboot_period: None,
            max_concurrent_machine_updates_absolute: Some(10),
            max_concurrent_machine_updates_percent: None,
        },
        max_find_by_ids: default_max_find_by_ids(),
        network_security_group: NetworkSecurityGroupConfig::default(),
        min_dpu_functioning_links: None,
        dpu_network_monitor_pinger_type: None,
        host_health: HostHealthConfig::default(),
        internet_l3_vni: 1337,
        measured_boot_collector: MeasuredBootMetricsCollectorConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(10),
        },
        machine_validation_config: MachineValidationConfig {
            enabled: true,
            ..MachineValidationConfig::default()
        },
        bypass_rbac: false,
        fnn: None,
        bios_profiles: HashMap::default(),
        selected_profile: libredfish::BiosProfileType::Performance,
        bom_validation: BomValidationConfig::default(),
        listen_mode: ListenMode::Tls,
        listen_only: false,
        nvlink_config: Some(NvLinkConfig::default()),
        dpa_config: Some(DpaConfig {
            enabled: true,
            mqtt_endpoint: "mqtt.forge".to_string(),
            mqtt_broker_port: 1884_u16,
            hb_interval: Duration::minutes(2),
            subnet_ip: Ipv4Addr::UNSPECIFIED,
            subnet_mask: 0_i32,
        }),
        power_manager_options: PowerManagerOptions {
            enabled: false,
            ..PowerManagerOptions::default()
        },
        auto_machine_repair_plugin: Default::default(),
        vmaas_config: Some(VmaasConfig {
            allow_instance_vf: true,
            hbn_reps: None,
            hbn_sfs: None,
            secondary_overlay_support: true,
            bridging: None,
            public_prefixes: vec![],
        }),
        mlxconfig_profiles: None,
        rack_management_enabled: false,
        force_dpu_nic_mode: false,
        rms_api_url: Some(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_string(),
        ),
        spdm_state_controller: SpdmStateControllerConfig {
            controller: StateControllerConfig::default(),
        },
        spdm: SpdmConfig {
            enabled: true,
            nras_config: Some(nras::Config::default()),
        },
        dsx_exchange_event_bus: None,
        use_onboard_nic: Arc::new(false.into()),
        dpf: crate::cfg::file::DpfConfig::default(),
        x86_pxe_boot_url_override: None,
        arm_pxe_boot_url_override: None,
    }
}

/// crate::sqlx_test shares the pool with all testcases in a file. If there are many testcases in a file,
/// test cases will start getting PoolTimedOut error. To avoid it, each test case will be assigned
/// its own pool.
async fn create_pool(current_pool: sqlx::PgPool) -> sqlx::PgPool {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is not set.");
    let db_options = current_pool.connect_options();
    let db: &str = db_options
        .get_database()
        .expect("No database is set initially.");

    let db_url = format!("{db_url}/{db}");

    use sqlx::ConnectOptions;
    let connect_options = PgConnectOptions::from_str(&db_url)
        .unwrap()
        .log_statements("INFO".parse().unwrap());

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(15)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect_with(connect_options)
        .await
        .expect("Pool creation failed.")
}

/// Creates an environment for unit-testing
///
/// This returns the `Api` object instance which can be used to simulate calls against
/// the Forge site controller, as well as mocks for dependent services that
/// can be inspected and passed to other systems.
pub async fn create_test_env(db_pool: sqlx::PgPool) -> TestEnv {
    create_test_env_with_overrides(db_pool, Default::default()).await
}

#[derive(Debug, Default)]
pub struct VerifierSimImpl {}

#[async_trait::async_trait]
impl Verifier for VerifierSimImpl {
    fn client(&self, _nras_config: nras::Config) -> Box<dyn nras::VerifierClient> {
        Box::new(VerifierClientSim::default())
    }
    async fn parse_attestation_outcome(
        &self,
        _nras_config: &nras::Config,
        _state: &RawAttestationOutcome,
    ) -> Result<ProcessedAttestationOutcome, NrasError> {
        Ok(ProcessedAttestationOutcome {
            attestation_passed: true,
            devices: HashMap::new(),
        })
    }
}

#[derive(Debug, Default)]
pub struct VerifierClientSim {}

#[async_trait]
impl VerifierClient for VerifierClientSim {
    async fn attest_gpu(
        &self,
        _device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        let verifier_response = RawAttestationOutcome {
            overall_outcome: ("JWT".to_string(), "All_good".to_string()),
            devices_outcome: HashMap::new(),
        };
        Ok(verifier_response)
    }

    async fn attest_dpu(
        &self,
        _device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        Err(NrasError::NotImplemented)
    }
    async fn attest_cx7(
        &self,
        _device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        Err(NrasError::NotImplemented)
    }
}

pub async fn create_test_env_with_overrides(
    db_pool: sqlx::PgPool,
    overrides: TestEnvOverrides,
) -> TestEnv {
    let db_pool = create_pool(db_pool).await;
    let work_lock_manager_handle = work_lock_manager::start(
        db_pool.clone(),
        work_lock_manager::KeepaliveConfig::default(),
    )
    .await
    .expect("work_lock_manager failed to start: no availble connections?");
    let test_meter = TestMeter::default();
    let credential_provider = Arc::new(TestCredentialProvider::default());
    populate_default_credentials(credential_provider.as_ref()).await;
    let certificate_provider = Arc::new(TestCertificateProvider::new());
    let redfish_sim = Arc::new(RedfishSim::default());
    let nmxm_sim: Arc<dyn NmxmClientPool> =
        Arc::new(if overrides.nmxm_default_partition == Some(true) {
            NmxmSimClient::with_default_partition()
        } else {
            NmxmSimClient::default()
        });

    let mut config = overrides.config.unwrap_or(get_config());
    if let Some(threshold) = overrides.dpu_agent_version_staleness_threshold {
        config.host_health.dpu_agent_version_staleness_threshold = threshold;
    }
    if let Some(prevent) = overrides.prevent_allocations_on_stale_dpu_agent_version {
        config
            .host_health
            .prevent_allocations_on_stale_dpu_agent_version = prevent;
    }
    let config = Arc::new(config);

    let ib_config = config.ib_config.clone().unwrap_or_default();
    let ib_fabric_manager_impl = ib::create_ib_fabric_manager(
        credential_provider.clone(),
        ib::IBFabricManagerConfig {
            allow_insecure_fabric_configuration: ib_config.allow_insecure,
            endpoints: if ib_config.enabled {
                config
                    .ib_fabrics
                    .iter()
                    .map(|(fabric_id, fabric_definition)| {
                        (fabric_id.clone(), fabric_definition.endpoints.clone())
                    })
                    .collect()
            } else {
                Default::default()
            },
            manager_type: if ib_config.enabled {
                IBFabricManagerType::Mock
            } else {
                IBFabricManagerType::Disable
            },
            fabric_manager_run_interval: std::time::Duration::from_secs(10),
            max_partition_per_tenant: IBFabricConfig::default_max_partition_per_tenant(),
            mtu: ib_config.mtu,
            rate_limit: ib_config.rate_limit,
            service_level: ib_config.service_level,
        },
    )
    .unwrap();

    let ib_fabric_manager = Arc::new(ib_fabric_manager_impl);
    let ib_fabric_monitor = IbFabricMonitor::new(
        db_pool.clone(),
        config.ib_fabrics.clone(),
        test_meter.meter(),
        ib_fabric_manager.clone(),
        config.clone(),
        work_lock_manager_handle.clone(),
    );

    let nvl_partition_monitor = NvlPartitionMonitor::new(
        db_pool.clone(),
        nmxm_sim.clone(),
        test_meter.meter(),
        config.nvlink_config.clone().unwrap(),
        config.host_health,
        work_lock_manager_handle.clone(),
    );

    let site_fabric_networks = overrides
        .site_prefixes
        .as_ref()
        .unwrap_or(&TEST_SITE_PREFIXES)
        .to_vec();
    let site_fabric_count = site_fabric_networks.len() as u8;
    println!("Fabric Prefix: {site_fabric_networks:?}");
    let site_fabric_prefixes = { SiteFabricPrefixList::from_ipnetwork_vec(site_fabric_networks) };

    let eth_virt_data = EthVirtData {
        asn: 65535,
        dhcp_servers: vec![FIXTURE_DHCP_RELAY_ADDRESS.to_string()],
        deny_prefixes: vec![],
        site_fabric_prefixes,
    };

    // Populate resource pools, leaving room for at least 5 networks, more if there are lots of
    // configured site prefixes
    let pool_size = site_fabric_count.max(5);
    let mut txn = db_pool.begin().await.unwrap();
    db::resource_pool::define_all_from(&mut txn, &pool_defs(pool_size))
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let common_pools =
        db::resource_pool::create_common_pools(db_pool.clone(), ["default".to_string()].into())
            .await
            .expect("Creating pools should work");

    let dyn_settings = crate::dynamic_settings::DynamicSettings {
        log_filter: Arc::new(ActiveLevel::new(
            EnvFilter::builder()
                .parse(std::env::var("RUST_LOG").unwrap_or("trace".to_string()))
                .unwrap(),
            None,
        )),
        create_machines: config.site_explorer.create_machines.clone(),
        bmc_proxy: config.site_explorer.bmc_proxy.clone(),
        tracing_enabled: Arc::new(false.into()),
    };

    let ipmi_tool = Arc::new(IPMIToolTestImpl {});

    let bmc_explorer = Arc::new(BmcEndpointExplorer::new(
        redfish_sim.clone(),
        ipmi_tool.clone(),
        credential_provider.clone(),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ));

    let reachability_params = ReachabilityParams {
        dpu_wait_time: Duration::seconds(0),
        power_down_wait: Duration::seconds(0),
        failure_retry_time: Duration::seconds(0),
        scout_reporting_timeout: config.machine_state_controller.scout_reporting_timeout,
    };

    let rms_sim = Arc::new(RmsSim);

    let api = Arc::new(Api {
        kube_client_provider: Arc::new(TestDpfKubeClient {}),
        runtime_config: config.clone(),
        credential_provider: credential_provider.clone(),
        certificate_provider: certificate_provider.clone(),
        database_connection: db_pool.clone(),
        redfish_pool: redfish_sim.clone(),
        eth_data: eth_virt_data.clone(),
        common_pools: common_pools.clone(),
        ib_fabric_manager: ib_fabric_manager.clone(),
        dynamic_settings: dyn_settings,
        endpoint_explorer: bmc_explorer,
        dpu_health_log_limiter: LogLimiter::default(),
        scout_stream_registry: scout_stream::ConnectionRegistry::new(),
        rms_client: rms_sim.as_rms_client(),
        nmxm_pool: nmxm_sim.clone(),
        work_lock_manager_handle: work_lock_manager_handle.clone(),
        machine_state_handler_enqueuer: Enqueuer::new(db_pool.clone()),
    });

    let attestation_enabled = config.attestation_enabled;
    let ipmi_tool = Arc::new(IPMIToolTestImpl {});
    let mut power_options: PowerOptionConfig = config.power_manager_options.clone().into();
    if let Some(v) = overrides.power_manager_enabled {
        power_options.enabled = v;
    }

    let dpf_config = if let Some(override_dpf_config) = overrides.dpf_config {
        override_dpf_config
    } else {
        DpfConfig::from(config.dpf.clone(), Arc::new(carbide_dpf::Production {}))
    };

    let machine_swap = SwapHandler {
        inner: Arc::new(Mutex::new(
            MachineStateHandlerBuilder::builder()
                .hardware_models(config.get_firmware_config())
                .reachability_params(reachability_params)
                .attestation_enabled(attestation_enabled)
                .common_pools(common_pools.clone())
                .dpu_enable_secure_boot(config.dpu_config.dpu_enable_secure_boot)
                .machine_validation_config(MachineValidationConfig {
                    enabled: config.machine_validation_config.enabled,
                    run_interval: config.machine_validation_config.run_interval,
                    tests: config.machine_validation_config.tests.clone(),
                    test_selection_mode: config.machine_validation_config.test_selection_mode,
                })
                .bom_validation(config.bom_validation)
                .instance_autoreboot_period(
                    config.machine_updater.instance_autoreboot_period.clone(),
                )
                .power_options_config(power_options)
                .dpf_config(dpf_config)
                .build(),
        )),
    };

    let spdm_swap = SwapHandler {
        inner: Arc::new(Mutex::new(SpdmAttestationStateHandler::new(
            Arc::new(VerifierSimImpl::default()),
            nras::Config::default(),
        ))),
    };

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: db_pool.clone(),
        redfish_client_pool: redfish_sim.clone(),
        ib_fabric_manager: ib_fabric_manager.clone(),
        ib_pools: common_pools.infiniband.clone(),
        ipmi_tool: ipmi_tool.clone(),
        site_config: config.clone(),
        dpa_info: None,
        rms_client: None,
    });

    let state_controller_id = uuid::Uuid::new_v4().to_string();

    let machine_controller = StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_machines", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(machine_swap.clone()))
        .io(Arc::new(MachineStateControllerIO {
            host_health: config.host_health,
        }))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let spdm_controller = StateController::<SpdmStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("spdm", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(spdm_swap.clone()))
        .io(Arc::new(SpdmStateControllerIO {}))
        .build_for_manual_iterations()
        .expect("Unable to build spdm state controller");

    let ib_swap = SwapHandler {
        inner: Arc::new(Mutex::new(IBPartitionStateHandler::default())),
    };

    let ib_controller = StateController::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_machines", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(ib_swap.clone()))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let network_swap = SwapHandler {
        inner: Arc::new(Mutex::new(NetworkSegmentStateHandler::new(
            overrides
                .network_segments_drain_period
                .unwrap_or(chrono::Duration::milliseconds(500)),
            common_pools.ethernet.pool_vlan_id.clone(),
            common_pools.ethernet.pool_vni.clone(),
        ))),
    };

    let mut network_controller = StateController::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_machines", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(network_swap.clone()))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let power_shelf_controller = StateController::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_power_shelves", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(PowerShelfStateHandler::default()))
        .build_for_manual_iterations()
        .expect("Unable to build PowerShelfStateController");

    let switch_controller = StateController::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_switches", test_meter.meter())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(SwitchStateHandler::default()))
        .build_for_manual_iterations()
        .expect("Unable to build state controller");

    let fake_endpoint_explorer = MockEndpointExplorer {
        reports: Arc::new(std::sync::Mutex::new(Default::default())),
    };

    // The API server is launched with a disabled site-explorer config so that it doesn't launch one
    // on its own. TestEnv's site_explorer is a separate instance talking to the same database that
    // *is* enabled, so it gets a different config. The purpose is so that tests can manually run
    // site explorer iterations to seed data/etc.
    let site_explorer = SiteExplorer::new(
        db_pool.clone(),
        SiteExplorerConfig {
            enabled: true,
            // run_interval shouldn't matter, this should not be run(), we only trigger intervals manually.
            run_interval: Duration::seconds(0).to_std().unwrap(),
            concurrent_explorations: 100,
            explorations_per_run: 100,
            create_machines: Arc::new(true.into()),
            machines_created_per_run: 1,
            override_target_ip: None,
            override_target_port: None,
            allow_zero_dpu_hosts: overrides.allow_zero_dpu_hosts.unwrap_or(false),
            bmc_proxy: Arc::new(Default::default()),
            allow_changing_bmc_proxy: None,
            reset_rate_limit: Duration::hours(1),
            admin_segment_type_non_dpu: Arc::new(false.into()),
            allocate_secondary_vtep_ip: true,
            create_power_shelves: Arc::new(true.into()),
            explore_power_shelves_from_static_ip: Arc::new(true.into()),
            power_shelves_created_per_run: 1,
            create_switches: Arc::new(true.into()),
            switches_created_per_run: 1,
            rotate_switch_nvos_credentials: Arc::new(false.into()),
            use_onboard_nic: Arc::new(false.into()),
        },
        test_meter.meter(),
        Arc::new(fake_endpoint_explorer.clone()),
        Arc::new(config.get_firmware_config()),
        common_pools.clone(),
        work_lock_manager_handle.clone(),
        rms_sim.as_rms_client(),
    );

    // Create some instance types
    let mut txn = api.txn_begin().await.unwrap();

    for _ in 0..3 {
        let uid = uuid::Uuid::new_v4();

        // Prepare some attributes for creation and comparison later
        let desired_capabilities = vec![InstanceTypeMachineCapabilityFilter {
            capability_type: MachineCapabilityType::Cpu,
            ..Default::default()
        }];

        let metadata = Metadata {
            name: format!("the best type {uid}"),
            description: "".to_string(),
            labels: HashMap::new(),
        };

        let id = InstanceTypeId::from(uid);

        let _it = create_instance_type(&mut txn, &id, &metadata, &desired_capabilities)
            .await
            .unwrap();
    }

    txn.commit().await.unwrap();

    // Create domain
    let domain: carbide_uuid::domain::DomainId = api
        .create_domain(Request::new(rpc::protos::dns::CreateDomainRequest {
            name: "dwrt1.com".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .id
        .map(::carbide_uuid::domain::DomainId::try_from)
        .unwrap()
        .unwrap();

    let (admin_segment, underlay_segment) = if overrides.create_network_segments.unwrap_or(true) {
        // Create admin network
        let admin = Some(create_admin_network_segment(&api).await);
        network_controller.run_single_iteration().await;
        network_controller.run_single_iteration().await;

        // Create underlay network
        let underlay = Some(create_underlay_network_segment(&api).await);
        network_controller.run_single_iteration().await;
        network_controller.run_single_iteration().await;

        (admin, underlay)
    } else {
        (None, None)
    };

    TestEnv {
        api,
        common_pools,
        config,
        pool: db_pool,
        redfish_sim,
        ib_fabric_manager,
        ipmi_tool,
        machine_state_controller: Arc::new(Mutex::new(machine_controller)),
        spdm_state_controller: Arc::new(Mutex::new(spdm_controller)),
        machine_state_handler: machine_swap,
        ib_fabric_monitor: Arc::new(ib_fabric_monitor),
        ib_partition_controller: Arc::new(Mutex::new(ib_controller)),
        #[allow(dead_code)]
        switch_controller: Arc::new(Mutex::new(switch_controller)),
        network_segment_controller: Arc::new(Mutex::new(network_controller)),
        #[allow(dead_code)]
        power_shelf_controller: Arc::new(Mutex::new(power_shelf_controller)),
        reachability_params,
        attestation_enabled,
        test_meter,
        site_explorer,
        nmxm_sim,
        endpoint_explorer: fake_endpoint_explorer,
        admin_segment,
        underlay_segment,
        domain: domain.into(),
        nvl_partition_monitor: Arc::new(Mutex::new(nvl_partition_monitor)),
        test_credential_provider: credential_provider.clone(),
        rms_sim,
    }
}

pub async fn get_instance_type_fixture_id(env: &TestEnv) -> String {
    // Find the existing instance types in the test env
    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    env.api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: existing_instance_type_ids,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types
        .pop()
        .unwrap()
        .id
}

pub async fn populate_network_security_groups(api: Arc<Api>) {
    // Create tenant orgs
    let default_tenant_org = "Tenant1";
    let _ = api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: default_tenant_org.to_string(),
            routing_profile_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: default_tenant_org.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    let tenant_org2 = "Tenant2";
    let _ = api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: tenant_org2.to_string(),
            routing_profile_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: tenant_org2.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Create default network security groups.
    let mut txn = api.txn_begin().await.unwrap();

    // Just a default ID for group and single rule.
    let uid = "fd3ab096-d811-11ef-8fe9-7be4b2483448";

    let rules = vec![network_security_group::NetworkSecurityGroupRule {
        id: Some(uid.to_string()),
        direction: network_security_group::NetworkSecurityGroupRuleDirection::Ingress,
        ipv6: false,
        src_port_start: Some(80),
        src_port_end: Some(32768),
        dst_port_start: Some(80),
        dst_port_end: Some(32768),
        protocol: network_security_group::NetworkSecurityGroupRuleProtocol::Any,
        action: network_security_group::NetworkSecurityGroupRuleAction::Deny,
        priority: 9001,
        src_net: network_security_group::NetworkSecurityGroupRuleNet::Prefix(
            "0.0.0.0/0".parse().unwrap(),
        ),
        dst_net: network_security_group::NetworkSecurityGroupRuleNet::Prefix(
            "0.0.0.0/0".parse().unwrap(),
        ),
    }];

    let metadata = Metadata {
        name: "default_network_security_group_1".to_string(),
        description: "".to_string(),
        labels: HashMap::new(),
    };

    let id = uid.parse().unwrap();

    let tenant_org = default_tenant_org.parse::<TenantOrganizationId>().unwrap();

    let _it =
        create_network_security_group(&mut txn, &id, &tenant_org, None, &metadata, false, &rules)
            .await
            .unwrap();

    // Create one more NSG with a different name.
    // The rules can be the same.
    // Just another default ID for group and single rule.
    let uid = "b65b13d6-d81c-11ef-9252-b346dc360bd4";
    let metadata = Metadata {
        name: "default_network_security_group_2".to_string(),
        description: "".to_string(),
        labels: HashMap::new(),
    };
    let id = uid.parse().unwrap();

    let _it =
        create_network_security_group(&mut txn, &id, &tenant_org, None, &metadata, false, &rules)
            .await
            .unwrap();

    // One more for the second tenant
    let uid = "ddfcabc4-92dc-41e2-874e-2c7eeb9fa156";
    let metadata = Metadata {
        name: "default_network_security_group_3".to_string(),
        description: "".to_string(),
        labels: HashMap::new(),
    };
    let id = uid.parse().unwrap();

    let _it = create_network_security_group(
        &mut txn,
        &id,
        &tenant_org2.parse::<TenantOrganizationId>().unwrap(),
        None,
        &metadata,
        false,
        &rules,
    )
    .await
    .unwrap();

    txn.commit().await.unwrap();
}

async fn populate_default_credentials(credential_provider: &dyn CredentialProvider) {
    credential_provider
        .set_credentials(
            &CredentialKey::DpuRedfish {
                credential_type: CredentialType::DpuHardwareDefault,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "dpuredfish_dpuhardwaredefault".to_string(),
            },
        )
        .await
        .unwrap();
    credential_provider
        .set_credentials(
            &CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "dpuredfish_sitedefault".to_string(),
            },
        )
        .await
        .unwrap();
    credential_provider
        .set_credentials(
            &CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            &Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "hostredfish_sitedefault".to_string(),
            },
        )
        .await
        .unwrap();
}

fn pool_defs(fabric_len: u8) -> HashMap<String, resource_pool::ResourcePoolDef> {
    let mut defs = HashMap::new();
    defs.insert(
        "ib_fabrics.default.pkey".to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "1".to_string(),
                end: "100".to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        model::resource_pool::common::VPC_DPU_LOOPBACK.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Ipv4,
            // Must match a network_prefix in fixtures/create_network_segment.sql
            prefix: None,
            ranges: vec![resource_pool::Range {
                start: "10.255.255.0".to_string(),
                end: "10.255.255.127".to_string(),
            }],
        },
    );
    defs.insert(
        model::resource_pool::common::LOOPBACK_IP.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Ipv4,
            // Must match a network_prefix in fixtures/create_network_segment.sql
            prefix: Some("172.20.0.0/24".to_string()),
            ranges: vec![],
        },
    );
    defs.insert(
        model::resource_pool::common::VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: 10_001.to_string(),
                end: (10_001 + fabric_len as u16 - 1).to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        model::resource_pool::common::VLANID.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: 1.to_string(),
                end: (1 + fabric_len as u16 - 1).to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        model::resource_pool::common::VPC_VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: 20001.to_string(),
                end: (20001 + fabric_len as u16 - 1).to_string(),
            }],
            prefix: None,
        },
    );

    defs.insert(
        model::resource_pool::common::EXTERNAL_VPC_VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: 50001.to_string(),
                end: (50001 + fabric_len as u16 - 1).to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        model::resource_pool::common::DPA_VNI.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: 30001.to_string(),
                end: (30001 + fabric_len as u16 - 1).to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        model::resource_pool::common::FNN_ASN.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: vec![resource_pool::Range {
                start: "30001".to_string(),
                end: "30035".to_string(),
            }],
            prefix: None,
        },
    );
    defs.insert(
        resource_pool::common::SECONDARY_VTEP_IP.to_string(),
        resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Ipv4,
            prefix: Some("172.30.0.0/24".to_string()),
            ranges: vec![],
        },
    );
    defs
}

/// Emulates the `DiscoveryCompleted` request of a DPU/Host
pub async fn discovery_completed(env: &TestEnv, machine_id: carbide_uuid::machine::MachineId) {
    let _response = env
        .api
        .discovery_completed(Request::new(rpc::forge::MachineDiscoveryCompletedRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
}

/// Fake an iteration of forge-dpu-agent requesting network config, applying it, and reporting back
pub async fn network_configured(env: &TestEnv, dpu_machine_ids: &Vec<MachineId>) {
    for dpu_machine_id in dpu_machine_ids {
        network_configured_with_health(env, dpu_machine_id, None).await
    }
}

/// Fake an iteration of forge-dpu-agent requesting network config, applying it, and reporting back.
/// When reporting back, the health reported by the DPU can be overrridden
pub async fn network_configured_with_health(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    dpu_health: Option<rpc::health::HealthReport>,
) {
    let network_config = env
        .api
        .get_managed_host_network_config(Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(*dpu_machine_id),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let instance_network_config_version =
        if network_config.instance_network_config_version.is_empty() {
            None
        } else {
            Some(network_config.instance_network_config_version.clone())
        };
    let instance: Option<rpc::Instance> = env
        .api
        .find_instance_by_machine_id(Request::new(*dpu_machine_id))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop();
    let instance_config_version = if let Some(instance) = instance {
        // If an instance is reported via this API, the version should match what we
        // get via the GetManagedHostNetworkConfig API
        if !network_config.use_admin_network {
            assert_eq!(
                instance_network_config_version.as_ref().unwrap().as_str(),
                instance.network_config_version,
                "Different network config versions reported via FindInstanceByMachineId and GetManagedHostNetworkConfig"
            );
        }
        Some(instance.config_version)
    } else {
        None
    };

    let interfaces = if network_config.use_admin_network {
        let iface = network_config
            .admin_interface
            .as_ref()
            .expect("use_admin_network true so admin_interface should be Some");
        vec![rpc::forge::InstanceInterfaceStatusObservation {
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
        let mut interfaces = vec![];
        for iface in network_config.tenant_interfaces.iter() {
            interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: None,
                addresses: vec![iface.ip.clone()],
                prefixes: vec![iface.interface_prefix.clone()],
                gateways: vec![iface.gateway.clone()],
                network_security_group: None,
                internal_uuid: iface.internal_uuid.clone(),
            });
        }
        interfaces
    };

    let dpu_health = dpu_health.unwrap_or_else(|| rpc::health::HealthReport {
        source: "forge-dpu-agent".to_string(),
        observed_at: None,
        successes: vec![],
        alerts: vec![],
    });

    let dpu_extension_services: Vec<rpc::forge::DpuExtensionServiceStatusObservation> =
        network_config
            .dpu_extension_services
            .iter()
            .map(
                |extension_service| rpc::forge::DpuExtensionServiceStatusObservation {
                    service_id: extension_service.service_id.clone(),
                    service_type: extension_service.service_type,
                    service_name: "".to_string(),
                    version: extension_service.version.to_string(),
                    state:
                        rpc::forge::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceRunning
                            as i32,
                    components: vec![],
                    message: "".to_string(),
                    removed: extension_service.removed.clone(),
                },
            )
            .collect();

    let status = rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(*dpu_machine_id),
        dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
        observed_at: None,
        dpu_health: Some(dpu_health),
        network_config_version: Some(network_config.managed_host_config_version.clone()),
        instance_id: network_config.instance_id,
        instance_config_version: instance_config_version.clone(),
        instance_network_config_version: instance_network_config_version.clone(),
        interfaces,
        network_config_error: None,
        client_certificate_expiry_unix_epoch_secs: None,
        fabric_interfaces: vec![],
        last_dhcp_requests: vec![],
        dpu_extension_service_version: network_config
            .instance
            .map(|instance| instance.dpu_extension_service_version),
        dpu_extension_services,
    };
    tracing::trace!(
        "network_configured machine={} instance_network={} instance={}",
        status.network_config_version.as_ref().unwrap(),
        instance_network_config_version.clone().unwrap_or_default(),
        instance_config_version.clone().unwrap_or_default(),
    );
    let _ = env
        .api
        .record_dpu_network_status(Request::new(status))
        .await
        .unwrap();
}

/// Fake hardware health service reporting health
pub async fn simulate_hardware_health_report(
    env: &TestEnv,
    host_machine_id: &MachineId,
    health_report: health_report::HealthReport,
) {
    use rpc::forge::HardwareHealthReport;
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .record_hardware_health_report(Request::new(HardwareHealthReport {
            machine_id: Some(*host_machine_id),
            report: Some(health_report.into()),
        }))
        .await
        .unwrap();
}

/// Send a health report override
pub async fn send_health_report_override(
    env: &TestEnv,
    machine_id: &MachineId,
    r#override: (HealthReport, OverrideMode),
) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .insert_health_report_override(Request::new(InsertHealthReportOverrideRequest {
            machine_id: Some(*machine_id),
            r#override: Some(HealthReportOverride {
                report: Some(r#override.0.into()),
                mode: r#override.1 as i32,
            }),
        }))
        .await
        .unwrap();
}

/// Remove a health report override
pub async fn remove_health_report_override(env: &TestEnv, machine_id: &MachineId, source: String) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .remove_health_report_override(Request::new(RemoveHealthReportOverrideRequest {
            machine_id: Some(*machine_id),
            source,
        }))
        .await
        .unwrap();
}

pub async fn forge_agent_control(
    env: &TestEnv,
    machine_id: carbide_uuid::machine::MachineId,
) -> rpc::forge::ForgeAgentControlResponse {
    let _ = reboot_completed(env, machine_id).await;

    env.api
        .forge_agent_control(Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner()
}

/// Create a managed host with 1 DPU (default config)
pub async fn create_managed_host(env: &TestEnv) -> TestManagedHost {
    let mh = site_explorer::new_host(env, ManagedHostConfig::default())
        .await
        .expect("Failed to create a new host");
    TestManagedHost {
        id: mh.host_snapshot.id,
        dpu_ids: mh.dpu_snapshots.iter().map(|dpu| dpu.id).collect(),
        api: env.api.clone(),
    }
}

/// Create a managed host with 1 DPU (default config)
pub async fn create_managed_host_with_dpf(env: &TestEnv) -> TestManagedHost {
    let dpu_config = DpuConfig::with_hardware_info_template(
        managed_host::HardwareInfoTemplate::Custom(dpu::DPU_BF3_INFO_JSON),
    );
    let mh_config = ManagedHostConfig::with_dpus(vec![dpu_config]);
    let mh = site_explorer::new_mock_host_with_dpf(env, mh_config)
        .await
        .expect("Failed to create a new host");
    TestManagedHost {
        id: mh.host_snapshot.id,
        dpu_ids: mh.dpu_snapshots.iter().map(|dpu| dpu.id).collect(),
        api: env.api.clone(),
    }
}

pub async fn create_managed_host_with_ek(env: &TestEnv, ek_cert: &[u8]) -> TestManagedHost {
    let host_config = ManagedHostConfig {
        tpm_ek_cert: TpmEkCertificate::from(ek_cert.to_vec()),
        ..Default::default()
    };

    create_managed_host_with_config(env, host_config.clone()).await
}

/// Create a managed host with `dpu_count` DPUs (default config)
pub async fn create_managed_host_multi_dpu(env: &TestEnv, dpu_count: usize) -> TestManagedHost {
    assert!(dpu_count >= 1, "need to specify at least 1 dpu");
    let config =
        ManagedHostConfig::with_dpus((0..dpu_count).map(|_| DpuConfig::default()).collect());
    let mh = site_explorer::new_host(env, config).await.unwrap();

    TestManagedHost {
        id: mh.host_snapshot.id,
        dpu_ids: mh.dpu_snapshots.iter().map(|dpu| dpu.id).collect(),
        api: env.api.clone(),
    }
}

/// Create a managed host with full config control
pub async fn create_managed_host_with_config(
    env: &TestEnv,
    config: ManagedHostConfig,
) -> TestManagedHost {
    let dpu_count = config.dpus.len();
    let mh = site_explorer::new_host(env, config)
        .await
        .expect("Failed to create a new host");

    let host_machine_id = mh.host_snapshot.id;

    let (id, dpu_ids) = match dpu_count {
        0 => (host_machine_id, vec![]),
        1 => (host_machine_id, vec![mh.dpu_snapshots[0].id]),
        _ => {
            let dpu_ids = mh
                .dpu_snapshots
                .iter()
                .map(|snapshot| snapshot.id)
                .collect();
            (host_machine_id, dpu_ids)
        }
    };
    TestManagedHost {
        id,
        dpu_ids,
        api: env.api.clone(),
    }
}

pub async fn create_host_with_machine_validation(
    env: &TestEnv,
    machine_validation_result_data: Option<rpc::forge::MachineValidationResult>,
    error: Option<String>,
) -> TestManagedHost {
    let mh = new_host_with_machine_validation(env, 1, machine_validation_result_data, error)
        .await
        .unwrap();
    TestManagedHost {
        id: mh.host_snapshot.id,
        dpu_ids: mh.dpu_snapshots.into_iter().map(|s| s.id).collect(),
        api: env.api.clone(),
    }
}

pub async fn create_managed_host_with_hardware_info_template(
    env: &TestEnv,
    hardware_info_template: managed_host::HardwareInfoTemplate,
) -> TestManagedHost {
    let config = ManagedHostConfig::with_hardware_info_template(hardware_info_template);
    let mh = site_explorer::new_host(env, config).await.unwrap();
    TestManagedHost {
        id: mh.host_snapshot.id,
        dpu_ids: mh.dpu_snapshots.into_iter().map(|s| s.id).collect(),
        api: env.api.clone(),
    }
}

pub async fn update_time_params(
    pool: &sqlx::PgPool,
    machine: &Machine,
    retry_count: i64,
    last_reboot_requested: Option<DateTime<Utc>>,
) {
    let mut txn = pool.begin().await.unwrap();
    let data = MachineLastRebootRequested {
        time: if let Some(last_reboot_requested) = last_reboot_requested {
            last_reboot_requested
        } else {
            machine.last_reboot_requested.as_ref().unwrap().time - Duration::minutes(1)
        },
        mode: machine.last_reboot_requested.as_ref().unwrap().mode,
        restart_verified: None,
        verification_attempts: None,
    };

    let last_reboot_time = machine.last_reboot_time.unwrap() - Duration::minutes(2i64);

    let ts = machine.last_reboot_requested.as_ref().unwrap().time - Duration::minutes(retry_count);
    let last_discovery_time = ts - Duration::minutes(1);

    let version = format!(
        "V{}-T{}",
        machine.current_version().version_nr(),
        ts.timestamp_micros()
    );

    let query = "UPDATE machines SET last_reboot_requested=$1, controller_state_version=$3, last_reboot_time=$4, last_discovery_time=$5 WHERE id=$2 RETURNING *";
    sqlx::query(query)
        .bind(sqlx::types::Json(&data))
        .bind(machine.id.to_string())
        .bind(version)
        .bind(last_reboot_time)
        .bind(last_discovery_time)
        .execute(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

pub async fn reboot_completed(
    env: &TestEnv,
    machine_id: carbide_uuid::machine::MachineId,
) -> rpc::forge::MachineRebootCompletedResponse {
    tracing::info!("Machine ={} rebooted", machine_id);
    env.api
        .reboot_completed(Request::new(rpc::forge::MachineRebootCompletedRequest {
            machine_id: Some(machine_id),
        }))
        .await
        .unwrap()
        .into_inner()
}

// Emulates the `MachineValidationComplete` request of a Host
pub async fn machine_validation_completed(
    env: &TestEnv,
    machine_id: &MachineId,
    machine_validation_error: Option<String>,
) {
    let response = forge_agent_control(env, *machine_id).await;
    let uuid = &response.data.unwrap().pair[1].value;

    let _response = env
        .api
        .machine_validation_completed(Request::new(
            rpc::forge::MachineValidationCompletedRequest {
                machine_id: Some(*machine_id),
                machine_validation_error,
                validation_id: Some(rpc::Uuid {
                    value: uuid.to_owned(),
                }),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// inject_machine_measurements injects auto-approved measurements
/// for a machine. This also will create a new profile and bundle,
/// if needed, as part of the auto-approval process.
pub async fn inject_machine_measurements(
    env: &TestEnv,
    machine_id: carbide_uuid::machine::MachineId,
) {
    let _response = env
        .api
        .add_measurement_trusted_machine(Request::new(
            rpc::protos::measured_boot::AddMeasurementTrustedMachineRequest {
                machine_id: machine_id.to_string(),
                approval_type: rpc::protos::measured_boot::MeasurementApprovedTypePb::Oneshot
                    as i32,
                pcr_registers: "0-1".to_string(),
                comments: "".to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let pcr_values: Vec<PcrRegisterValue> = vec![
        PcrRegisterValue {
            pcr_register: 0,
            sha_any: "aa".to_string(),
        },
        PcrRegisterValue {
            pcr_register: 1,
            sha_any: "bb".to_string(),
        },
    ];

    let _response = env
        .api
        .attest_candidate_machine(Request::new(
            rpc::protos::measured_boot::AttestCandidateMachineRequest {
                machine_id: machine_id.to_string(),
                pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `MachineValidationComplete` request of a Host
pub async fn persist_machine_validation_result(
    env: &TestEnv,
    machine_validation_result: rpc::forge::MachineValidationResult,
) {
    env.api
        .persist_validation_result(Request::new(
            rpc::forge::MachineValidationResultPostRequest {
                result: Some(machine_validation_result),
            },
        ))
        .await
        .unwrap()
        .into_inner();
}

/// Emulates the `get_machine_validation_results` request of a Host
pub async fn get_machine_validation_results(
    env: &TestEnv,
    machine_id: Option<&MachineId>,
    include_history: bool,
    validation_id: Option<rpc::common::Uuid>,
) -> rpc::forge::MachineValidationResultList {
    env.api
        .get_machine_validation_results(Request::new(rpc::forge::MachineValidationGetRequest {
            machine_id: machine_id.copied(),
            include_history,
            validation_id,
        }))
        .await
        .unwrap()
        .into_inner()
}

/// Emulates the `get_machine_validation_runs` request of a Host
pub async fn get_machine_validation_runs(
    env: &TestEnv,
    machine_id: &MachineId,
    include_history: bool,
) -> rpc::forge::MachineValidationRunList {
    env.api
        .get_machine_validation_runs(Request::new(
            rpc::forge::MachineValidationRunListGetRequest {
                machine_id: Some(*machine_id),
                include_history,
            },
        ))
        .await
        .unwrap()
        .into_inner()
}

// Emulates the `OnDemandMachineValidation` request of a Host
pub async fn on_demand_machine_validation(
    env: &TestEnv,
    machine_id: carbide_uuid::machine::MachineId,
    tags: Vec<String>,
    allowed_tests: Vec<String>,
    run_unverfied_tests: bool,
    contexts: Vec<String>,
) -> rpc::forge::MachineValidationOnDemandResponse {
    env.api
        .on_demand_machine_validation(Request::new(rpc::forge::MachineValidationOnDemandRequest {
            machine_id: Some(machine_id),
            action: rpc::forge::machine_validation_on_demand_request::Action::Start.into(),
            tags,
            allowed_tests,
            run_unverfied_tests,
            contexts,
        }))
        .await
        .unwrap()
        .into_inner()
}

pub async fn update_machine_validation_run(
    env: &TestEnv,
    validation_id: Option<rpc::common::Uuid>,
    duration_to_complete: Option<rpc::Duration>,
    total: u32,
) -> rpc::forge::MachineValidationRunResponse {
    env.api
        .update_machine_validation_run(Request::new(rpc::forge::MachineValidationRunRequest {
            validation_id,
            duration_to_complete,
            total,
        }))
        .await
        .unwrap()
        .into_inner()
}

pub async fn get_vpc_fixture_id(env: &TestEnv) -> VpcId {
    db::vpc::find_by_name(&mut env.pool.begin().await.unwrap(), "test vpc 1")
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .id
}

/// A hot swappable machine state handler.
/// Allows modifying the handler behavior without reconstructing the machine
/// state controller (which leads to stale metrics being saved).
#[derive(Debug, Clone)]
pub struct SwapHandler<H: StateHandler> {
    pub inner: Arc<Mutex<H>>,
}

#[async_trait::async_trait]
impl<H: StateHandler> StateHandler for SwapHandler<H>
where
    H::ObjectId: Send + Sync,
    H::State: Send + Sync,
    H::ControllerState: Send + Sync,
    H::ContextObjects: Send + Sync,
{
    type ObjectId = H::ObjectId;
    type State = H::State;
    type ControllerState = H::ControllerState;
    type ContextObjects = H::ContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        self.inner
            .lock()
            .await
            .handle_object_state(object_id, state, controller_state, ctx)
            .await
    }
}

fn create_random_self_signed_cert() -> Vec<u8> {
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let CertifiedKey { cert, .. } = generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed cert");
    cert.der().to_vec()
}
