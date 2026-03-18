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

use mac_address::MacAddress;
use rpc::{NetworkInterface, PciDeviceProperties};

use crate::hw;

// This type describes Intel® Ethernet Network Adapter E810.
pub struct NicIntelX550 {
    pub mac_address: MacAddress,
}

impl NicIntelX550 {
    pub fn to_nic(&self) -> hw::nic::Nic<'static> {
        hw::nic::Nic {
            mac_address: self.mac_address,
            serial_number: None,
            manufacturer: None,
            model: None,
            description: None,
            part_number: None,
            firmware_version: None,
            is_mat_dpu: false,
        }
    }

    pub fn discovery_info(&self, path: &str, slot: &str, numa_node: i32) -> NetworkInterface {
        NetworkInterface {
            mac_address: self.mac_address.to_string(),
            pci_properties: Some(PciDeviceProperties {
                vendor: "Intel Corporation".into(),
                device: "Ethernet Controller X550".into(),
                path: path.into(),
                numa_node,
                description: Some("Ethernet Controller X550".into()),
                slot: Some(slot.into()),
            }),
        }
    }
}
