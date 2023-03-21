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
pub mod common;
use common::api_fixtures::create_test_env;
use std::net::{IpAddr, Ipv4Addr};
use std::task::Poll;
use std::time::Duration;

use carbide::db::dpu_machine::DpuMachine;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::kubernetes::{VpcApi, VpcApiCreateResourceGroupResult, VpcApiError};
use carbide::model::machine::{MachineState, ManagedHostState};
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::vpc_resources::managed_resource::ManagedResource;
use ipnetwork::IpNetwork;
use log::LevelFilter;

const DPU_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");
const HOST_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd99");

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

    async fn try_delete_leaf(&self, _dpu_machine_id: uuid::Uuid) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_create_managed_resources(
        &self,
        _managed_resources: Vec<ManagedResource>,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_update_leaf(
        &self,
        _dpu_machine_id: uuid::Uuid,
        _host_admin_ip: Ipv4Addr,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_delete_managed_resources(
        &self,
        _instance_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_monitor_leaf(&self, _dpu_machine_id: uuid::Uuid) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }
}

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn validate_state_till_ready(pool: sqlx::PgPool) -> sqlx::Result<()> {
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(1);

    let mut txn = pool.begin().await?;
    let env = create_test_env(pool.clone(), Default::default());
    // Reset Machine state to initial.
    DpuMachine::update_state(
        &mut txn,
        DPU_MACHINE_ID,
        ManagedHostState::DPUNotReady(MachineState::Init),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;
    let dpu = Machine::find_one(&mut txn, DPU_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        dpu.current_state(),
        ManagedHostState::DPUNotReady(..)
    ));
    // Update reboot time.
    dpu.update_reboot_time(&mut txn).await.unwrap();
    dpu.update_discovery_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let handler = MachineStateHandler::default();

    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;

    // Now machine should be in HostNotReady state.
    // Simulate Host boot setup.
    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostNotReady(MachineState::Init)
    ));
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostNotReady(MachineState::WaitingForDiscovery)
    ));

    txn.commit().await.unwrap();
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;

    // Now state should be hostnotready discovered.
    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    host.update_reboot_time(&mut txn).await.unwrap();
    host.update_discovery_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;
    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostNotReady(MachineState::Discovered)
    ));
    txn.commit().await.unwrap();

    // Now state should be READY.
    let mut txn = pool.begin().await?;
    host.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;

    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    let dpu = Machine::find_one(&mut txn, DPU_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    Ok(())
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn validate_state_from_cleanup_to_ready(pool: sqlx::PgPool) -> sqlx::Result<()> {
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(1);

    let env = create_test_env(pool.clone(), Default::default());
    let mut txn = pool.begin().await?;
    // Reset Machine state to initial.
    DpuMachine::update_state(
        &mut txn,
        DPU_MACHINE_ID,
        ManagedHostState::WaitingForCleanup(carbide::model::machine::CleanupState::HostCleanup),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    host.update_reboot_time(&mut txn).await.unwrap();
    host.update_cleanup_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let handler = MachineStateHandler::default();

    // Current State: HostCleanup
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;

    // Now machine should be in HostNotReady(WaitingForDiscovery) state.
    // Simulate Host boot setup.
    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostNotReady(MachineState::Discovered)
    ));
    host.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    // Current: Discovered
    env.run_machine_state_controller_iteration(DPU_MACHINE_ID, &handler)
        .await;

    // Now state should be READY.
    let mut txn = pool.begin().await?;
    let host = Machine::find_one(&mut txn, HOST_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    let dpu = Machine::find_one(&mut txn, DPU_MACHINE_ID, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    Ok(())
}
