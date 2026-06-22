/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use model::site_explorer::{
    Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport, EndpointType,
    NicMode, PCIeDevice,
};
use rpc::forge_server::Forge;

use crate::tests::common::api_fixtures::create_test_env;

fn pcie(part: &str, fw: &str, serial: &str, id: &str) -> PCIeDevice {
    PCIeDevice {
        description: Some(format!("NVIDIA BlueField-3 {part}")),
        firmware_version: Some(fw.to_string()),
        gpu_vendor: None,
        id: Some(id.to_string()),
        manufacturer: Some("Nvidia".to_string()),
        name: Some("Network Device".to_string()),
        part_number: Some(part.to_string()),
        serial_number: Some(serial.to_string()),
        status: None,
    }
}

// Exercises the full explored-device read path: seed a host whose Redfish PCIe
// inventory shows a NIC-mode DPU plus that DPU's own BMC endpoint, then confirm
// the handler projects the device and joins it to its DPU BMC by serial.
#[crate::sqlx_test()]
async fn test_get_explored_mlx_devices(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let host_ip = IpAddr::from_str("192.0.2.20")?;
    let dpu_ip = IpAddr::from_str("192.0.2.50")?;

    // The host BMC reports a NIC-mode DPU (900-9D3B4) running outdated NIC FW.
    let host_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        systems: vec![ComputerSystem {
            pcie_devices: vec![pcie(
                "900-9D3B4-00EN-EA0",
                "32.38.1002",
                "MT2403X00984",
                "188-0",
            )],
            ..Default::default()
        }],
        ..Default::default()
    };
    // The DPU's own BMC endpoint, keyed by the matching serial, reporting NIC mode.
    let dpu_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            serial_number: Some("MT2403X00984".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Nic),
                ..Default::default()
            },
            ..Default::default()
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            model: Some("NVIDIA BlueField 3".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };

    let mut txn = env.pool.begin().await?;
    db::explored_endpoints::insert(host_ip, &host_report, false, &mut txn).await?;
    db::explored_endpoints::insert(dpu_ip, &dpu_report, false, &mut txn).await?;
    txn.commit().await?;

    let devices = env
        .api
        .get_explored_mlx_devices(tonic::Request::new(
            ::rpc::site_explorer::GetExploredMlxDevicesRequest { host_bmc_ip: None },
        ))
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .devices;

    // Only the host's BlueField device; the DPU endpoint contributes none.
    assert_eq!(devices.len(), 1);
    let device = &devices[0];
    assert_eq!(device.host_bmc_ip, "192.0.2.20");
    assert_eq!(device.part_number.as_deref(), Some("900-9D3B4-00EN-EA0"));
    assert_eq!(device.firmware_version.as_deref(), Some("32.38.1002"));
    assert_eq!(device.serial_number.as_deref(), Some("MT2403X00984"));
    assert_eq!(
        device.device_kind,
        ::rpc::site_explorer::MlxDeviceKind::Bf3NicMode as i32
    );
    // Joined to its DPU endpoint by serial.
    assert_eq!(device.dpu_bmc_ip.as_deref(), Some("192.0.2.50"));
    assert_eq!(
        device.nic_mode,
        Some(::rpc::site_explorer::NicMode::Nic as i32)
    );

    // The host filter scopes the result to a single host BMC.
    let other_host = env
        .api
        .get_explored_mlx_devices(tonic::Request::new(
            ::rpc::site_explorer::GetExploredMlxDevicesRequest {
                host_bmc_ip: Some("198.51.100.1".to_string()),
            },
        ))
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .devices;
    assert!(other_host.is_empty());

    Ok(())
}
