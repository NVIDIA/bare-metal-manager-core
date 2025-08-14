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

use super::tpm_attestation::{AK_NAME_SERIALIZED, AK_PUB_SERIALIZED, EK_PUB_SERIALIZED};
use crate::db;
use crate::db::network_prefix::NetworkPrefix;
use crate::db::{ObjectColumnFilter, network_prefix};
use crate::model::machine::{MachineState::UefiSetup, UefiSetupInfo, UefiSetupState};
use crate::model::{hardware_info::HardwareInfo, machine::ManagedHostState};
use crate::tests::common::api_fixtures::{
    TestEnv, forge_agent_control, managed_host::ManagedHostConfig,
};
use forge_uuid::machine::MachineId;
use rpc::machine_discovery::AttestKeyInfo;
use rpc::{
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
    forge::{DhcpDiscovery, forge_agent_control_response::Action, forge_server::Forge},
};
use strum::IntoEnumIterator;
use tonic::Request;

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
    let predicted_host = db::machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    let prefix = NetworkPrefix::find_by(
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
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: host_config.dhcp_mac_address().to_string(),
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
) -> ::rpc::common::MachineId {
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

pub async fn host_uefi_setup(
    env: &TestEnv,
    host_machine_id: &MachineId,
    host_rpc_machine_id: ::rpc::common::MachineId,
) {
    for state in UefiSetupState::iter() {
        if state == UefiSetupState::UnlockHost {
            // This state is reserved for legacy hosts--newly ingested hosts will never get here
            continue;
        }

        env.run_machine_state_controller_iteration_until_state_matches(
            host_machine_id,
            1,
            ManagedHostState::HostInit {
                machine_state: UefiSetup {
                    uefi_setup_info: UefiSetupInfo {
                        uefi_password_jid: None,
                        uefi_setup_state: state,
                    },
                },
            },
        )
        .await;

        let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
        assert_eq!(response.action, Action::Noop as i32);
    }
}
