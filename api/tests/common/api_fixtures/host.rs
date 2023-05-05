/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Contains host related fixtures

use carbide::{
    db::vpc_resource_leaf::VpcResourceLeaf,
    model::{
        hardware_info::HardwareInfo,
        machine::{
            machine_id::{try_parse_machine_id, MachineId},
            ManagedHostState,
        },
    },
    state_controller::machine::handler::MachineStateHandler,
};
use rpc::{
    forge::{forge_agent_control_response::Action, forge_server::Forge, DhcpDiscovery},
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use crate::common::api_fixtures::{discovery_completed, forge_agent_control, update_bmc_metadata};

use super::TestEnv;

const TEST_DATA_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/model/hardware_info/test_data"
);

/// MAC address that is used by the Host that is created by the fixture
pub const FIXTURE_HOST_MAC_ADDRESS: &str = "03:11:21:31:41:52";

pub const FIXTURE_HOST_BMC_IP_ADDRESS: &str = "233.233.233.3";
pub const FIXTURE_HOST_BMC_MAC_ADDRESS: &str = "11:22:33:44:55:67";

pub const FIXTURE_HOST_BMC_ADMIN_USER_NAME: &str = "forge_admin_host";

/// Creates a `HardwareInfo` object which represents a Host
pub fn create_host_hardware_info() -> HardwareInfo {
    let path = format!("{}/x86_info.json", TEST_DATA_DIR);
    let data = std::fs::read(path).unwrap();
    let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
    assert!(!info.is_dpu());
    info
}

/// Uses the `discover_dhcp` API to discover a Host with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_discover_dhcp(
    env: &TestEnv,
    mac_address: &str,
    dpu_machine_id: &MachineId,
) -> rpc::Uuid {
    let mut txn = env.pool.begin().await.unwrap();
    let leaf = VpcResourceLeaf::find(&mut txn, dpu_machine_id)
        .await
        .unwrap();
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: leaf.loopback_ip_address().unwrap().to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Emulates Host Machine Discovery (submitting hardware information) for the
/// Host that uses a certain `machine_interface_id`
pub async fn host_discover_machine(
    env: &TestEnv,
    machine_interface_id: rpc::Uuid,
) -> rpc::MachineId {
    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(create_host_hardware_info()).unwrap(),
            )),
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}

/// Creates a Machine Interface and Machine for a Host
///
/// Returns the ID of the created machine
pub async fn create_host_machine(env: &TestEnv, dpu_machine_id: &MachineId) -> rpc::MachineId {
    let machine_interface_id =
        host_discover_dhcp(env, FIXTURE_HOST_MAC_ADDRESS, dpu_machine_id).await;

    let handler = MachineStateHandler::default();
    let host_machine_id = host_discover_machine(env, machine_interface_id).await;
    let host_machine_id = try_parse_machine_id(&host_machine_id).unwrap();
    let host_rpc_machine_id: rpc::MachineId = host_machine_id.to_string().into();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        dpu_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: carbide::model::machine::MachineState::WaitingForDiscovery,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Discovery as i32);

    update_bmc_metadata(
        env,
        host_rpc_machine_id.clone(),
        FIXTURE_HOST_BMC_IP_ADDRESS,
        FIXTURE_HOST_BMC_ADMIN_USER_NAME.to_string(),
    )
    .await;

    discovery_completed(env, host_rpc_machine_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        dpu_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: carbide::model::machine::MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Noop as i32);
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        dpu_machine_id,
        &handler,
        1,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();

    host_rpc_machine_id
}
