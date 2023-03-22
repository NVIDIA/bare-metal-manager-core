/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};

use ipnetwork::IpNetwork;
use tonic::Request;

use crate::common::api_fixtures::{
    create_test_env,
    dpu::{create_dpu_hardware_info, dpu_discover_dhcp},
};
use carbide::{
    db::dpu_machine::DpuMachine,
    kubernetes::{VpcApi, VpcApiCreateResourceGroupResult, VpcApiError},
    model::machine::{machine_id::MachineId, ManagedHostState, ManagedHostStateSnapshot},
    state_controller::{
        controller::StateController,
        machine::io::MachineStateControllerIO,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
        },
    },
    vpc_resources::managed_resource::ManagedResource,
};
use rpc::{forge::forge_server::Forge, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};

#[derive(Debug, Default, Clone)]
pub struct TestMachineStateHandler {
    /// The total count for the handler
    pub count: Arc<AtomicUsize>,
    /// We count for every machine ID how often the handler was called
    pub counts_per_id: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait::async_trait]
impl StateHandler for TestMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;

    async fn handle_object_state(
        &self,
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        assert_eq!(state.dpu_snapshot.machine_id, *machine_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(machine_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MockVpcApi {}

#[async_trait::async_trait]
impl VpcApi for MockVpcApi {
    async fn try_create_resource_group(
        &self,
        _network_prefix_id: uuid::Uuid,
        _prefix: IpNetwork,
        _gateway: Option<IpNetwork>,
    ) -> Result<Poll<VpcApiCreateResourceGroupResult>, VpcApiError> {
        panic!("Not used in this test")
    }

    async fn try_delete_resource_group(
        &self,
        _network_prefix_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_create_leaf(&self, _dpu: DpuMachine) -> Result<Poll<IpAddr>, VpcApiError> {
        Ok(Poll::Ready(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
    }

    async fn try_delete_leaf(&self, _dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        panic!("Not used in this test")
    }

    async fn try_create_managed_resources(
        &self,
        _managed_resources: Vec<ManagedResource>,
    ) -> Result<Poll<()>, VpcApiError> {
        panic!("Not used in this test.")
    }

    async fn try_update_leaf(
        &self,
        _dpu_machine_id: &MachineId,
        _host_admin_ip: Ipv4Addr,
    ) -> Result<Poll<()>, VpcApiError> {
        panic!("Not used in this test")
    }

    async fn try_delete_managed_resources(
        &self,
        _instance_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        panic!("Not used in this test")
    }

    async fn try_monitor_leaf(&self, _dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }
}

#[sqlx::test(fixtures(
    "../../fixtures/create_domain",
    "../../fixtures/create_vpc",
    "../../fixtures/create_network_segment",
))]
async fn iterate_over_all_machines(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool.clone(), Default::default());

    // Insert some machines
    let dpu_macs = &[
        "11:22:33:44:55:01",
        "11:22:33:44:55:02",
        "11:22:33:44:55:03",
        "11:22:33:44:55:04",
    ];
    let mut machine_ids = Vec::new();
    for mac in &dpu_macs[..] {
        let interface_id = dpu_discover_dhcp(&env, mac).await;

        let mut hardware_info = create_dpu_hardware_info();
        hardware_info.dmi_data.as_mut().unwrap().product_serial = format!("DPU_{}", mac);
        let response = env
            .api
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(interface_id),
                discovery_data: Some(DiscoveryData::Info(
                    DiscoveryInfo::try_from(hardware_info).unwrap(),
                )),
            }))
            .await
            .unwrap()
            .into_inner();

        let machine_id = response.machine_id.expect("machine_id must be set");
        machine_ids.push(machine_id);
    }

    let machine_handler = Arc::new(TestMachineStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_iterations = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;
    let expected_total_count = expected_iterations * dpu_macs.len() as f64;

    let test_api = Arc::new(env.api);
    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            StateController::<MachineStateControllerIO>::builder()
                .iteration_time(Duration::from_millis(100))
                .database(pool.clone())
                .vpc_api(Arc::new(MockVpcApi {}))
                .forge_api(test_api.clone())
                .state_handler(machine_handler.clone())
                .build()
                .unwrap(),
        );
    }

    tokio::time::sleep(TEST_TIME).await;
    drop(handles);
    // Wait some extra time until the controller background task shuts down
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = machine_handler.count.load(Ordering::SeqCst) as f64;
    assert!(
        count > 0.75 * expected_total_count && count < 1.25 * expected_total_count,
        "Expected count of {}, but got {}",
        expected_total_count,
        count
    );

    for machine_id in machine_ids {
        let guard = machine_handler.counts_per_id.lock().unwrap();
        let count = guard
            .get(&machine_id.to_string())
            .cloned()
            .unwrap_or_default() as f64;

        assert!(
            count > 0.75 * expected_iterations && count < 1.25 * expected_iterations,
            "Expected count of {}, but got {}",
            expected_iterations,
            count
        );
    }

    Ok(())
}
