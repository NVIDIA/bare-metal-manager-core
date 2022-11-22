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

//! Contains DPU related fixtures

use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery},
    MachineDiscoveryInfo,
};
use tonic::Request;

use super::TestApi;

mod dpu_discovery_data;

/// MAC address that is used by the DPU that is created by the fixture
pub const FIXTURE_DPU_MAC_ADDRESS: &str = "01:11:21:31:41:51";

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine(api: &TestApi) -> rpc::Uuid {
    let machine_interface_id = dpu_discover_dhcp(api, FIXTURE_DPU_MAC_ADDRESS).await;
    dpu_discover_machine(api, machine_interface_id).await
    // TODO: Call the steps for submitting credentials if necessary
}

/// Uses the `discover_dhcp` API to discover a DPU with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_discover_dhcp(api: &TestApi, mac_address: &str) -> rpc::Uuid {
    let response = api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: "192.0.2.1".to_string(),
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
pub async fn dpu_discover_machine(api: &TestApi, machine_interface_id: rpc::Uuid) -> rpc::Uuid {
    let response = api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(dpu_discovery_data::create_dpu_discovery_data()),
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}
