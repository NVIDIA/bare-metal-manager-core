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

use carbide::db::machine::Machine;
use carbide::db::network_prefix::NetworkPrefix;
use carbide::db::UuidKeyedObjectFilter;
use carbide::{
    cfg::DpuFwUpdateConfig,
    db::machine_interface::MachineInterface,
    model::{
        hardware_info::HardwareInfo,
        machine::{
            machine_id::{try_parse_machine_id, MachineId},
            ManagedHostState,
        },
    },
    state_controller::{machine::handler::MachineStateHandler, metrics::IterationMetrics},
};
use rpc::{
    forge::{forge_agent_control_response::Action, forge_server::Forge, DhcpDiscovery},
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use crate::common::api_fixtures::{
    discovery_completed, forge_agent_control, managed_host::ManagedHostConfig, update_bmc_metadata,
    TestEnv,
};

use super::FIXTURE_DHCP_RELAY_ADDRESS;

const TEST_DATA_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/model/hardware_info/test_data"
);

pub const FIXTURE_HOST_BMC_VERSION: &str = "4.3";
pub const FIXTURE_HOST_BMC_FIRMWARE_VERSION: &str = "5.4";

pub const FIXTURE_HOST_BMC_ADMIN_USER_NAME: &str = "forge_admin_host";

/// Creates a `HardwareInfo` object which represents a Host
pub fn create_host_hardware_info(host_config: &ManagedHostConfig) -> HardwareInfo {
    let path = format!("{}/x86_info.json", TEST_DATA_DIR);
    let data = std::fs::read(path).unwrap();
    let mut info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
    info.tpm_ek_certificate = Some(host_config.host_tpm_ek_cert.clone());
    info.dmi_data.as_mut().unwrap().product_serial =
        format!("Host_{}", host_config.host_mac_address);
    // TODO: Patch hardware info with correct MAC addresses
    assert!(!info.is_dpu());
    info
}

/// Uses the `discover_dhcp` API to discover a Host BMC with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_bmc_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Uses the `discover_dhcp` API to discover a Host with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_discover_dhcp(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
) -> rpc::Uuid {
    let mut txn = env.pool.begin().await.unwrap();
    let loopback_ip = super::dpu::loopback_ip(&mut txn, dpu_machine_id).await;
    let predicted_host = Machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    let prefix = NetworkPrefix::find_by_segment(
        &mut txn,
        UuidKeyedObjectFilter::One(predicted_host.interfaces()[0].segment_id()),
    )
    .await
    .unwrap()
    .remove(0);

    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: host_config.host_mac_address.to_string(),
            relay_address: loopback_ip.to_string(),
            vendor_string: None,
            link_address: Some(prefix.gateway.unwrap().to_string()),
            circuit_id: None,
            remote_id: None,
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
    host_config: &ManagedHostConfig,
    machine_interface_id: rpc::Uuid,
) -> rpc::MachineId {
    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(create_host_hardware_info(host_config)).unwrap(),
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
pub async fn create_host_machine(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
) -> rpc::MachineId {
    use carbide::model::machine::{LockdownInfo, LockdownMode, LockdownState, MachineState};
    let bmc_machine_interface_id =
        host_bmc_discover_dhcp(env, &host_config.host_bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        MachineInterface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let host_bmc_ip = bmc_interface.addresses()[0].address;
    txn.rollback().await.unwrap();

    let machine_interface_id = host_discover_dhcp(env, host_config, dpu_machine_id).await;

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        env.reachability_params,
    );
    let host_machine_id = host_discover_machine(env, host_config, machine_interface_id).await;
    let host_machine_id = try_parse_machine_id(&host_machine_id).unwrap();
    let host_rpc_machine_id: rpc::MachineId = host_machine_id.to_string().into();

    let mut txn = env.pool.begin().await.unwrap();
    let mut iteration_metrics = IterationMetrics::default();

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::WaitingForDiscovery,
        },
        &mut iteration_metrics,
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Discovery as i32);

    update_bmc_metadata(
        env,
        host_rpc_machine_id.clone(),
        &host_bmc_ip.to_string(),
        FIXTURE_HOST_BMC_ADMIN_USER_NAME.to_string(),
        host_config.host_bmc_mac_address.to_string(),
        FIXTURE_HOST_BMC_VERSION.to_owned(),
        FIXTURE_HOST_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    discovery_completed(env, host_rpc_machine_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: LockdownInfo {
                    state: LockdownState::WaitForDPUUp,
                    mode: LockdownMode::Enable,
                },
            },
        },
        &mut iteration_metrics,
    )
    .await;
    txn.commit().await.unwrap();

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    super::network_configured(env, dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered,
        },
        &mut iteration_metrics,
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Noop as i32);
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        &handler,
        1,
        &mut txn,
        ManagedHostState::Ready,
        &mut iteration_metrics,
    )
    .await;
    txn.commit().await.unwrap();

    host_rpc_machine_id
}
