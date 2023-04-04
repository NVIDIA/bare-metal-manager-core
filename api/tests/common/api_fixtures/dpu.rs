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

use carbide::{
    model::{
        hardware_info::HardwareInfo,
        machine::{machine_id::try_parse_machine_id, ManagedHostState},
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

use crate::common::api_fixtures::{discovery_completed, update_bmc_metadata};

use super::{TestEnv, FIXTURE_DHCP_RELAY_ADDRESS};

/// MAC address that is used by the DPU that is created by the fixture
pub const FIXTURE_DPU_MAC_ADDRESS: &str = "01:11:21:31:41:51";

/// IP Address that is used for the DPU BMC
/// TODO: There exists no equivalent MachineInterfaceAddress entry for this one,
/// and it supports only a single DPU Machine
/// We might need a more extensive BMC simulation for this
pub const FIXTURE_DPU_BMC_IP_ADDRESS: &str = "233.233.233.2";
pub const FIXTURE_DPU_BMC_MAC_ADDRESS: &str = "11:22:33:44:55:66";

pub const FIXTURE_DPU_BMC_ADMIN_USER_NAME: &str = "forge_admin";

pub const FIXTURE_DPU_SSH_USERNAME: &str = "forge";
pub const FIXTURE_DPU_SSH_PASSWORD: &str = "asdhjkf";

pub const FIXTURE_DPU_HBN_USERNAME: &str = "cumulus";
pub const FIXTURE_DPU_HBN_PASSWORD: &str = "a9123";

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine(env: &TestEnv) -> rpc::MachineId {
    let machine_interface_id = dpu_discover_dhcp(env, FIXTURE_DPU_MAC_ADDRESS).await;
    let dpu_machine_id = dpu_discover_machine(env, machine_interface_id).await;
    let handler = MachineStateHandler::default();

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
    update_bmc_metadata(
        env,
        dpu_rpc_machine_id.clone(),
        FIXTURE_DPU_BMC_IP_ADDRESS,
        FIXTURE_DPU_BMC_ADMIN_USER_NAME.to_string(),
        FIXTURE_DPU_BMC_MAC_ADDRESS.to_string(),
    )
    .await;

    discovery_completed(env, dpu_rpc_machine_id.clone()).await;
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &dpu_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::HostNotReady(carbide::model::machine::MachineState::Init),
    )
    .await;
    txn.commit().await.unwrap();

    dpu_rpc_machine_id
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
    machine_interface_id: rpc::Uuid,
) -> rpc::MachineId {
    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(create_dpu_hardware_info()).unwrap(),
            )),
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
pub fn create_dpu_hardware_info() -> HardwareInfo {
    let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
    let data = std::fs::read(path).unwrap();
    let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
    assert!(info.is_dpu());
    info
}
