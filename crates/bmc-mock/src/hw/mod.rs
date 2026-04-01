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

//! Submodules of this module defines support of specific hardware
//! (i.e. how this hardware is represented via Redfish).

/// Description of NIC card.
pub mod nic;

/// Support of NVIDIA Bluefield3 DPU.
pub mod bluefield3;

/// Support of Dell PowerEdge R750 servers.
pub mod dell_poweredge_r750;

/// Support of Wiwynn GB200 NVL servers.
pub mod wiwynn_gb200_nvl;

/// Support of Lenovo GB300 NVL servers.
pub mod lenovo_gb300_nvl;

/// Support of LiteOn Power Shelf.
pub mod liteon_power_shelf;

/// Support of NVIDIA Switch ND5200_LD.
pub mod nvidia_switch_nd5200_ld;

/// Support of NVIDIA DGX H100.
pub mod nvidia_dgx_h100;

/// Common support of GB200 and GB300
pub mod nvidia_gbx00;

/// GB200 CPU/GPU
pub mod nvidia_gb200;

/// GB300 CPU/GPU
pub mod nvidia_gb300;

/// Intel E810 NIC.
pub mod nic_intel_e810;

/// Intel X550 NIC.
pub mod nic_intel_x550;

/// Intel I210 NIC.
pub mod nic_intel_i210;

/// NVIDIA ConnectX-7.
pub mod nic_nvidia_cx7;

use bmc_vendor::BMCVendor;

pub fn bmc_vendor_to_udev_dmi(v: BMCVendor) -> &'static str {
    match v {
        BMCVendor::Lenovo => "Lenovo",
        BMCVendor::Dell => "Dell Inc.",
        BMCVendor::Nvidia => "https://www.mellanox.com",
        BMCVendor::Supermicro => "Supermicro",
        BMCVendor::Hpe => "HPE",
        BMCVendor::LenovoAMI => "Unknown",
        BMCVendor::Liteon => "Unknown",
        BMCVendor::Unknown => "Unknown",
    }
}
