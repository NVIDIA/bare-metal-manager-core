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

use carbide::model::hardware_info::HardwareInfo;
use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery},
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use super::TestApi;

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
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(create_dpu_hardware_info()).unwrap(),
            )),
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
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
