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

use bmc_explorer::hw::HwType;
use bmc_explorer::nv_generate_exploration_report;
use bmc_explorer::test_support::detect_hw_type;
use bmc_mock::test_support;
use model::site_explorer::EndpointType;
use tokio::test;

/// A Lenovo GB300 (AMI BMC) must classify as the GB300 platform regardless of the
/// host BMC vendor. GB300 is detected from the NVIDIA "NVIDIA GB300" GPU chassis
/// (`is_gb300()`), so this also guards the detection decouple: the platform is
/// resolved up front from the HGX signature, with the ODM only selecting the variant.
#[test]
async fn explore_lenovo_gb300() {
    let h = test_support::lenovo_gb300_bmc().await;
    let config = common::explorer_config();

    // Decisive assertion: resolves to LenovoGb300 (the GB300 platform), proving
    // GB300 was recognized on an AMI host. Passes before and after the decouple.
    assert_eq!(
        detect_hw_type(h.service_root.clone(), &config)
            .await
            .unwrap(),
        Some(HwType::LenovoGb300),
    );

    let report = nv_generate_exploration_report(h.service_root, &config)
        .await
        .unwrap();
    assert_eq!(report.endpoint_type, EndpointType::Bmc);
    // LenovoGb300 -> BMCVendor::LenovoAMI; proves GB300 was recognized on an AMI host.
    assert_eq!(report.vendor, Some(bmc_vendor::BMCVendor::LenovoAMI));
    assert!(!report.systems.is_empty(), "systems must be present");
    assert!(!report.chassis.is_empty(), "chassis must be present");
}
