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

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use db::{ObjectColumnFilter, network_prefix};
use model::hardware_info::HardwareInfo;
use model::machine::MachineState::UefiSetup;
use model::machine::{ManagedHostState, UefiSetupInfo, UefiSetupState};
use rpc::forge::forge_agent_control_response::Action;
use rpc::forge::forge_server::Forge;
use rpc::machine_discovery::AttestKeyInfo;
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use strum::IntoEnumIterator;
use tonic::Request;

use super::tpm_attestation::{AK_NAME_SERIALIZED, AK_PUB_SERIALIZED, EK_PUB_SERIALIZED};
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::{TestEnv, TestMachine, forge_agent_control};
use crate::tests::common::rpc_builder::DhcpDiscovery;

pub const X86_INFO_JSON: &[u8] =
    include_bytes!("../../../../../api-model/src/hardware_info/test_data/x86_info.json");
// TODO: Remove when there's no longer a need to handle the old topology format
pub const X86_V1_CPU_INFO_JSON: &[u8] =
    include_bytes!("../../../../../api-model/src/hardware_info/test_data/x86_v1_cpu_info.json");
pub const GB200_COMPUTE_TRAY_1_INFO_JSON: &[u8] = include_bytes!(
    "../../../../../api-model/src/hardware_info/test_data/gb200_compute_tray_1_info.json"
);
pub const GB200_COMPUTE_TRAY_2_INFO_JSON: &[u8] = include_bytes!(
    "../../../../../api-model/src/hardware_info/test_data/gb200_compute_tray_2_info.json"
);
/// Uses the `discover_dhcp` API to discover a Host with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_discover_dhcp(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
) -> MachineInterfaceId {
    let mut txn = env.pool.begin().await.unwrap();
    let loopback_ip = super::dpu::loopback_ip(&mut txn, dpu_machine_id).await;
    let predicted_host = db::machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    let prefix = db::network_prefix::find_by(
        &mut txn,
        ObjectColumnFilter::One(
            network_prefix::SegmentIdColumn,
            &predicted_host.interfaces[0].segment_id,
        ),
    )
    .await
    .unwrap()
    .remove(0);

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(host_config.dhcp_mac_address(), loopback_ip)
                .link_address(prefix.gateway.unwrap())
                .tonic_request(),
        )
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
    machine_interface_id: MachineInterfaceId,
) -> MachineId {
    let mut discovery_info = DiscoveryInfo::try_from(HardwareInfo::from(host_config)).unwrap();

    discovery_info.attest_key_info = Some(AttestKeyInfo {
        ek_pub: EK_PUB_SERIALIZED.to_vec(),
        ak_pub: AK_PUB_SERIALIZED.to_vec(),
        ak_name: AK_NAME_SERIALIZED.to_vec(),
    });

    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}

pub async fn host_uefi_setup(env: &TestEnv, host_machine_id: &MachineId) {
    let machine = TestMachine::new(*host_machine_id, env.api.clone());

    // Wait until we are past through the last UefiSetupState and then assert we went through all
    const MAX_ITERATIONS: usize = 20;
    for _ in 0..MAX_ITERATIONS {
        env.run_machine_state_controller_iteration().await;
        let history = machine.parsed_history(Some(10)).await;

        let mut found_all = true;
        for state in UefiSetupState::iter().filter(|state|
        // These states are reserved for legacy hosts--newly ingested hosts will never get here
        *state != UefiSetupState::UnlockHost && *state != UefiSetupState::LockdownHost)
        {
            if !history.iter().any(|entry| {
                *entry
                    == ManagedHostState::HostInit {
                        machine_state: UefiSetup {
                            uefi_setup_info: UefiSetupInfo {
                                uefi_password_jid: None,
                                uefi_setup_state: state.clone(),
                            },
                        },
                    }
            }) {
                found_all = false;
                break;
            }
        }

        if found_all {
            tracing::info!("Host machine UEFI setup completed");
            return;
        }

        let response = forge_agent_control(env, *host_machine_id).await;
        assert_eq!(response.action, Action::Noop as i32);
    }

    panic!(
        "Host machine did not went through all UEFI setup states within {MAX_ITERATIONS} iterations"
    );
}
