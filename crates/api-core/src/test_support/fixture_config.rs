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

use std::sync::atomic::{AtomicU32, Ordering};

use carbide_utils::test_support::certs::create_random_self_signed_cert;
use model::expected_machine::ExpectedMachineData;
use model::hardware_info::TpmEkCertificate;
use model::machine::ManagedHostState;
use model::site_explorer::NicMode;
use model::test_support::managed_host::REQUIRED_IB_GUIDS;
use model::test_support::{DpuConfig, HardwareInfoTemplate, ManagedHostConfig};

use crate::test_support::{ib_guid_pool, mac_address_pool};

static NEXT_DPU_SERIAL: AtomicU32 = AtomicU32::new(1);
static NEXT_HOST_SERIAL: AtomicU32 = AtomicU32::new(1);

pub trait FixtureDefault {
    fn default() -> Self;
}

pub trait DpuConfigExt {
    fn with_serial(serial: String) -> Self;
    fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self;
}

impl FixtureDefault for DpuConfig {
    fn default() -> Self {
        Self {
            serial: format!(
                "MT2333X{:05X}",
                NEXT_DPU_SERIAL.fetch_add(1, Ordering::Relaxed)
            ),
            host_mac_address: mac_address_pool::HOST_MAC_ADDRESS_POOL.allocate(),
            oob_mac_address: mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL.allocate(),
            bmc_mac_address: mac_address_pool::DPU_BMC_MAC_ADDRESS_POOL.allocate(),
            bmc_firmware_version: carbide_firmware::defaults::BF3_BMC_VERSION.to_string(),
            last_exploration_error: None,
            override_hosts_uefi_device_path: None,
            hardware_info_template: HardwareInfoTemplate::Default,
            nic_mode: Some(NicMode::Dpu),
        }
    }
}

impl DpuConfigExt for DpuConfig {
    fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..DpuConfig::default()
        }
    }

    fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self {
        Self {
            hardware_info_template,
            ..DpuConfig::default()
        }
    }
}

pub trait ManagedHostConfigExt {
    fn with_serial(serial: String) -> Self;
    fn with_dpus(dpus: Vec<DpuConfig>) -> Self;
    fn with_expected_state(expected_state: ManagedHostState) -> Self;
    fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self;
    fn with_expected_machine_data(expected_machine_data: ExpectedMachineData) -> Self;
    fn with_admin_dhcp_fallback(self) -> Self;
}

impl FixtureDefault for ManagedHostConfig {
    fn default() -> Self {
        Self {
            serial: format!(
                "VVG1{:05X}",
                NEXT_HOST_SERIAL.fetch_add(1, Ordering::Relaxed)
            ),
            bmc_mac_address: mac_address_pool::HOST_BMC_MAC_ADDRESS_POOL.allocate(),
            tpm_ek_cert: TpmEkCertificate::from(create_random_self_signed_cert()),
            dpus: vec![DpuConfig::default()],
            non_dpu_macs: vec![mac_address_pool::HOST_NON_DPU_MAC_ADDRESS_POOL.allocate()],
            expected_state: ManagedHostState::Ready,
            // Create 6 IB GUIDs - which is what is required by x86_info.json.
            ib_guids: std::iter::repeat_with(|| ib_guid_pool::IB_GUID_POOL.allocate())
                .take(REQUIRED_IB_GUIDS)
                .collect(),
            auto_assign_sku_in_fixture: true,
            hardware_info_template: HardwareInfoTemplate::Default,
            expected_machine_data: None,
            vendor: Some(bmc_vendor::BMCVendor::Dell),
            admin_dhcp_fallback: false,
        }
    }
}

impl ManagedHostConfigExt for ManagedHostConfig {
    fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..ManagedHostConfig::default()
        }
    }

    fn with_dpus(dpus: Vec<DpuConfig>) -> Self {
        Self {
            dpus,
            ..ManagedHostConfig::default()
        }
    }

    fn with_expected_state(expected_state: ManagedHostState) -> Self {
        Self {
            expected_state,
            ..ManagedHostConfig::default()
        }
    }

    fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self {
        Self {
            hardware_info_template,
            ..ManagedHostConfig::default()
        }
    }

    fn with_admin_dhcp_fallback(mut self) -> Self {
        self.admin_dhcp_fallback = true;
        self
    }

    fn with_expected_machine_data(expected_machine_data: ExpectedMachineData) -> Self {
        Self {
            expected_machine_data: Some(expected_machine_data),
            ..ManagedHostConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use model::test_support::DpuConfig;

    use super::FixtureDefault as _;

    #[test]
    fn dpu_fixture_bmc_firmware_version_matches_default() {
        assert_eq!(
            DpuConfig::default().bmc_firmware_version,
            carbide_firmware::defaults::BF3_BMC_VERSION
        );
    }
}
