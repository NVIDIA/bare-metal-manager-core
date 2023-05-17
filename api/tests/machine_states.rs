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
use std::net::{IpAddr, Ipv4Addr};
use std::task::Poll;

use carbide::db::dpu_machine::DpuMachine;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::kubernetes::{VpcApi, VpcApiCreateResourceGroupResult, VpcApiError};
use carbide::model::machine::machine_id::MachineId;
use carbide::model::machine::ManagedHostState;
use carbide::vpc_resources::managed_resource::ManagedResource;
use common::api_fixtures::create_test_env;
use ipnetwork::IpNetwork;

#[derive(Debug)]
pub struct MockVpcApi {}

#[async_trait::async_trait]
impl VpcApi for MockVpcApi {
    async fn try_create_resource_group(
        &self,
        _network_prefix_id: uuid::Uuid,
        _prefix: IpNetwork,
        _gateway: Option<IpNetwork>,
        _vlan_id: Option<i16>,
        _vni: Option<i32>,
    ) -> Result<Poll<VpcApiCreateResourceGroupResult>, VpcApiError> {
        panic!("Not used in this test")
    }

    async fn try_delete_resource_group(
        &self,
        _network_prefix_id: uuid::Uuid,
    ) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }

    async fn try_create_leaf(
        &self,
        _dpu: DpuMachine,
        _address: IpAddr,
    ) -> Result<Poll<IpAddr>, VpcApiError> {
        Ok(Poll::Ready(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
    }

    async fn try_delete_leaf(&self, _dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
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
        _dpu_machine_id: &MachineId,
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

    async fn try_monitor_leaf(&self, _dpu_machine_id: &MachineId) -> Result<Poll<()>, VpcApiError> {
        Ok(Poll::Ready(()))
    }
}

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
}
