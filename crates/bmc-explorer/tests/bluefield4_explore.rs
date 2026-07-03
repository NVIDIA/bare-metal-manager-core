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
mod common;

use bmc_explorer::nv_generate_exploration_report;
use bmc_mock::{DpuMachineInfo, DpuSettings, HostHardwareType, test_support};
use mac_address::MacAddress;
use model::site_explorer::EndpointType;
use tokio::test;

#[test]
async fn explore_bluefield4_and_generate_machine_id_from_bluefield_bmc_chassis_serial() {
    let h = test_support::dell_poweredge_r760_bluefield4_bmc(DpuMachineInfo {
        hw_type: HostHardwareType::DellPowerEdgeR760Bf4,
        bmc_mac_address: MacAddress::new([0x02, 0x00, 0x00, 0xbf, 0x04, 0x01]),
        host_mac_address: MacAddress::new([0x02, 0x00, 0x00, 0xbf, 0x04, 0x02]),
        oob_mac_address: MacAddress::new([0x02, 0x00, 0x00, 0xbf, 0x04, 0x03]),
        serial: "MT2610604VN4".to_string(),
        settings: DpuSettings::default(),
    })
    .await;
    let mut report = nv_generate_exploration_report(h.service_root, &common::explorer_config())
        .await
        .unwrap();

    assert_eq!(report.endpoint_type, EndpointType::Bmc);
    assert_eq!(report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));

    let system = report.systems.first().expect("systems must be present");
    assert_eq!(system.id, "Bluefield");
    assert!(
        system.serial_number.is_none(),
        "BF4 Redfish reports the usable serial on chassis, not system"
    );

    let chassis_ids: Vec<&str> = report
        .chassis
        .iter()
        .map(|chassis| chassis.id.as_str())
        .collect();
    assert!(
        chassis_ids.contains(&"Bluefield_BMC"),
        "Bluefield_BMC chassis must be present: {chassis_ids:?}"
    );
    assert!(
        chassis_ids.contains(&"Card1"),
        "Card1 chassis must be present: {chassis_ids:?}"
    );
    let bmc_chassis_serial = report
        .chassis
        .iter()
        .find(|chassis| chassis.id == "Bluefield_BMC")
        .and_then(|chassis| chassis.serial_number.as_deref());
    assert_eq!(bmc_chassis_serial, Some("MT2610604VN4"));

    assert!(
        report
            .service
            .iter()
            .any(|service| service.id == "FirmwareInventory"),
        "firmware inventory service must be present"
    );

    let machine_id = *report
        .generate_machine_id(false)
        .expect("BF4 report should have enough collected data for machine ID")
        .expect("BF4 report should generate a DPU machine ID");

    assert!(machine_id.machine_type().is_dpu());
    assert_eq!(
        machine_id.to_string(),
        "fm100dsje1vlqbfpt0vn3hkuijsm07hpd78ctlfhrje2q8ssnj20ke32rdg"
    );
    assert_eq!(report.machine_id, Some(machine_id));
}

#[test]
async fn explore_b4240v_and_generate_machine_id() {
    let h = test_support::nvidia_dgx_vr_bluefield4_dpu_bmc(DpuSettings::default()).await;
    let mut report = nv_generate_exploration_report(h.service_root, &common::explorer_config())
        .await
        .expect("B4240V exploration should succeed");

    assert_eq!(report.endpoint_type, EndpointType::Bmc);
    assert_eq!(report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));
    assert!(report.chassis.iter().any(|chassis| {
        chassis.id == "Bluefield_BMC" && chassis.model.as_deref() == Some("B4240V")
    }));

    let machine_id = report
        .generate_machine_id(false)
        .expect("B4240V report should have enough collected data for machine ID")
        .expect("B4240V report should generate a DPU machine ID");
    assert!(machine_id.machine_type().is_dpu());
}
