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

//! Contains DPU related fixtures

use std::net::IpAddr;

use carbide::{
    cfg::{default_dpu_models, DpuFwUpdateConfig},
    db::{
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
    },
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
    forge::{
        forge_server::Forge,
        machine_credentials_update_request::{CredentialPurpose, Credentials},
        DhcpDiscovery, MachineCredentialsUpdateRequest,
    },
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use crate::common::api_fixtures::{
    discovery_completed, managed_host::ManagedHostConfig, network_configured, update_bmc_metadata,
    TestEnv, FIXTURE_DHCP_RELAY_ADDRESS,
};

pub const FIXTURE_DPU_BMC_VENDOR_STRING: &str = "NVIDIA/BF/BMC";
pub const FIXTURE_DPU_BMC_VERSION: &str = "2.1";
pub const FIXTURE_DPU_BMC_FIRMWARE_VERSION: &str = "3.2";

pub const FIXTURE_DPU_BMC_ADMIN_USER_NAME: &str = "forge_admin";

pub const FIXTURE_DPU_SSH_USERNAME: &str = "forge";
pub const FIXTURE_DPU_SSH_PASSWORD: &str = "asdhjkf";

pub const FIXTURE_DPU_HBN_USERNAME: &str = "cumulus";
pub const FIXTURE_DPU_HBN_PASSWORD: &str = "a9123";

/// DPU firmware version that is reported by DPU objects created via `create_dpu_hardware_info`.
pub const DEFAULT_DPU_FIRMWARE_VERSION: &str = "1.2.3";

/// The version identifier that is used by dpu-agent in unit-tests
pub const TEST_DPU_AGENT_VERSION: &str = "test";

/// The version of HBN reported in unit-tests
pub const TEST_DOCA_HBN_VERSION: &str = "1.5.0-doca2.2.0";
/// The version of doca-telemetry reported in unit-tests
pub const TEST_DOCA_TELEMETRY_VERSION: &str = "1.14.2-doca2.2.0";

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine(env: &TestEnv, host_config: &ManagedHostConfig) -> rpc::MachineId {
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        default_dpu_models(),
        env.reachability_params,
    );

    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(env, host_config).await;
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.to_string().into();
    let mut txn = env.pool.begin().await.unwrap();

    // Simulate the ForgeAgentControl request of the DPU
    let agent_control_response = env
        .api
        .forge_agent_control(tonic::Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(dpu_rpc_machine_id.clone()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Noop as i32
    );

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler.clone(),
        4,
        &mut txn,
        ManagedHostState::DPUNotReady {
            machine_state: carbide::model::machine::MachineState::WaitingForNetworkConfig,
        },
    )
    .await;

    network_configured(env, &dpu_machine_id).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler,
        4,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: carbide::model::machine::MachineState::WaitingForDiscovery,
        },
    )
    .await;
    txn.commit().await.unwrap();

    dpu_rpc_machine_id
}

pub async fn create_dpu_machine_in_waiting_for_network_install(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
) -> (MachineId, MachineId) {
    let bmc_machine_interface_id =
        dpu_bmc_discover_dhcp(env, &host_config.dpu_bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        MachineInterface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let dpu_bmc_ip = bmc_interface.addresses()[0].address;
    txn.rollback().await.unwrap();

    let machine_interface_id =
        dpu_discover_dhcp(env, &host_config.dpu_oob_mac_address.to_string()).await;
    let dpu_rpc_machine_id = dpu_discover_machine(env, host_config, machine_interface_id).await;
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        default_dpu_models(),
        env.reachability_params,
    );

    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    tracing::debug!("Attempting to create machine inventory");
    create_machine_inventory(env, &dpu_machine_id).await;

    // Simulate the ForgeAgentControl request of the DPU
    let agent_control_response = env
        .api
        .forge_agent_control(tonic::Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(dpu_rpc_machine_id.clone()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Discovery as i32
    );

    update_dpu_machine_credentials(env, dpu_rpc_machine_id.clone()).await;

    // TODO: This it not really happening in the current version of forge-scout.
    // But it's in the test setup to verify reading back submitted credentials
    // TODO: This IP is allocated by carbide. We need to use the right one
    update_bmc_metadata(
        env,
        dpu_rpc_machine_id.clone(),
        &dpu_bmc_ip.to_string(),
        FIXTURE_DPU_BMC_ADMIN_USER_NAME.to_string(),
        host_config.dpu_bmc_mac_address.to_string(),
        FIXTURE_DPU_BMC_VERSION.to_owned(),
        FIXTURE_DPU_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    discovery_completed(env, dpu_rpc_machine_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_machine_id = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap()
        .id()
        .clone();

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler,
        4,
        &mut txn,
        ManagedHostState::DPUNotReady {
            machine_state: carbide::model::machine::MachineState::WaitingForNetworkInstall,
        },
    )
    .await;

    txn.commit().await.unwrap();

    (dpu_machine_id, host_machine_id)
}

pub async fn create_machine_inventory(env: &TestEnv, machine_id: &MachineId) {
    tracing::debug!("Creating machine inventory for {}", machine_id);
    env.api
        .update_agent_reported_inventory(Request::new(rpc::forge::DpuAgentInventoryReport {
            machine_id: Some(rpc::MachineId {
                id: machine_id.to_string(),
            }),
            inventory: Some(rpc::forge::MachineInventory {
                components: vec![
                    rpc::forge::MachineInventorySoftwareComponent {
                        name: "doca-hbn".to_string(),
                        version: TEST_DOCA_HBN_VERSION.to_string(),
                        url: "nvcr.io/nvidia/doca/".to_string(),
                    },
                    rpc::forge::MachineInventorySoftwareComponent {
                        name: "doca-telemetry".to_string(),
                        version: TEST_DOCA_TELEMETRY_VERSION.to_string(),
                        url: "nvcr.io/nvidia/doca/".to_string(),
                    },
                ],
            }),
        }))
        .await
        .unwrap()
        .into_inner()
}

/// Uses the `discover_dhcp` API to discover a DPU BMC with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_bmc_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: Some("NVIDIA/BF/BMC".to_string()),
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

/// Uses the `discover_dhcp` API to discover a DPU with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
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

/// Uses the `discover_dhcp` API to discover a DPU BMC
///
/// Returns the created `machine_interface_id`
pub async fn dpu_discover_bmc_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: Some(FIXTURE_DPU_BMC_VENDOR_STRING.to_string()),
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

/// Emulates DPU Machine Discovery (submitting hardware information) for the
/// DPU that uses a certain `machine_interface_id`
pub async fn dpu_discover_machine(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    machine_interface_id: rpc::Uuid,
) -> rpc::MachineId {
    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(create_dpu_hardware_info(host_config)).unwrap(),
            )),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}

/// Emulates the `UpdateMachineCredentials` request of a DPU
pub async fn update_dpu_machine_credentials(env: &TestEnv, dpu_machine_id: rpc::MachineId) {
    let _response = env
        .api
        .update_machine_credentials(Request::new(MachineCredentialsUpdateRequest {
            machine_id: Some(dpu_machine_id),
            credentials: vec![
                Credentials {
                    user: FIXTURE_DPU_SSH_USERNAME.to_string(),
                    password: FIXTURE_DPU_SSH_PASSWORD.to_string(),
                    credential_purpose: CredentialPurpose::LoginUser as i32,
                },
                Credentials {
                    user: FIXTURE_DPU_HBN_USERNAME.to_string(),
                    password: FIXTURE_DPU_HBN_PASSWORD.to_string(),
                    credential_purpose: CredentialPurpose::Hbn as i32,
                },
            ],
        }))
        .await
        .unwrap()
        .into_inner();
}

const TEST_DATA_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/model/hardware_info/test_data"
);

/// Creates a `HardwareInfo` object which represents a DPU
pub fn create_dpu_hardware_info(host_config: &ManagedHostConfig) -> HardwareInfo {
    let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
    let data = std::fs::read(path).unwrap();
    let mut info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
    info.dpu_info.as_mut().unwrap().factory_mac_address = host_config.host_mac_address.to_string();
    info.dmi_data.as_mut().unwrap().product_serial =
        format!("DPU_{}", host_config.dpu_oob_mac_address);
    // TODO: Patch in the correct DPU mac addresses
    info.dpu_info.as_mut().unwrap().firmware_version = DEFAULT_DPU_FIRMWARE_VERSION.to_owned();
    assert!(info.is_dpu());
    info
}

// Convenience method for the tests to get a machine's loopback IP
pub async fn loopback_ip(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dpu_machine_id: &MachineId,
) -> IpAddr {
    let dpu = Machine::find_one(txn, dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    IpAddr::V4(dpu.loopback_ip().unwrap())
}

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine_with_discovery_error(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    discovery_error: Option<String>,
) -> rpc::MachineId {
    let bmc_machine_interface_id =
        dpu_bmc_discover_dhcp(env, &host_config.dpu_bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        MachineInterface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let dpu_bmc_ip = bmc_interface.addresses()[0].address;
    txn.rollback().await.unwrap();

    let machine_interface_id =
        dpu_discover_dhcp(env, &host_config.dpu_oob_mac_address.to_string()).await;
    let dpu_machine_id = dpu_discover_machine(env, host_config, machine_interface_id).await;
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        default_dpu_models(),
        env.reachability_params,
    );

    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.to_string().into();

    // Simulate the ForgeAgentControl request of the DPU
    let agent_control_response = env
        .api
        .forge_agent_control(tonic::Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(dpu_rpc_machine_id.clone()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Discovery as i32
    );

    update_dpu_machine_credentials(env, dpu_rpc_machine_id.clone()).await;

    // TODO: This it not really happening in the current version of forge-scout.
    // But it's in the test setup to verify reading back submitted credentials
    // TODO: This IP is allocated by carbide. We need to use the right one
    update_bmc_metadata(
        env,
        dpu_rpc_machine_id.clone(),
        &dpu_bmc_ip.to_string(),
        FIXTURE_DPU_BMC_ADMIN_USER_NAME.to_string(),
        host_config.dpu_bmc_mac_address.to_string(),
        FIXTURE_DPU_BMC_VERSION.to_owned(),
        FIXTURE_DPU_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    discovery_completed(env, dpu_rpc_machine_id.clone(), discovery_error).await;
    env.run_machine_state_controller_iteration(handler).await;

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    match machine.current_state() {
        ManagedHostState::Failed { .. } => {}
        s => {
            panic!("Incorrect state: {}", s);
        }
    }

    txn.commit().await.unwrap();

    dpu_rpc_machine_id
}
