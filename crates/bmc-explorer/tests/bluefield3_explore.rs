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
#![recursion_limit = "256"]

use bmc_explorer::nv_generate_exploration_report;
use bmc_mock::{DpuSettings, test_support};
use model::site_explorer::EndpointType;
use tokio::test;

#[test]
async fn explore_bluefield3_baseline() {
    let bmc = test_support::dell_poweredge_r750_bluefield3_bmc(DpuSettings::default());
    let report = nv_generate_exploration_report(bmc, None).await.unwrap();

    assert_eq!(report.endpoint_type, EndpointType::Bmc);
    assert_eq!(report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));
    assert!(!report.systems.is_empty(), "systems must be present");
    assert!(!report.chassis.is_empty(), "chassis must be present");
    assert!(
        report
            .service
            .iter()
            .any(|service| service.id == "FirmwareInventory"),
        "firmware inventory service must be present"
    );
    assert!(
        report
            .machine_setup_status
            .as_ref()
            .is_some_and(|status| !status.diffs.is_empty() || status.is_done),
        "machine setup status must be present and structurally valid"
    );
}

#[test]
async fn explore_bluefield3_without_system_eth_interfaces() {
    let settings = DpuSettings {
        exposes_oob_eth: false,
        ..Default::default()
    };
    let bmc = test_support::dell_poweredge_r750_bluefield3_bmc(settings);
    let report = nv_generate_exploration_report(bmc, None).await.unwrap();
    assert_eq!(report.endpoint_type, EndpointType::Bmc);
    assert_eq!(report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));
    assert_eq!(
        report
            .systems
            .first()
            .map(|v| v.ethernet_interfaces.is_empty()),
        Some(true)
    );
}
