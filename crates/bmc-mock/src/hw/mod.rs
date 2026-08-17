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
pub(super) mod nic;

/// Support of NVIDIA Bluefield3 DPU.
pub(super) mod bluefield3;

/// Support of NVIDIA Bluefield4 DPU.
pub(super) mod bluefield4;

/// Generic AMI server.
pub(super) mod generic_ami;

/// Support of HPE ProLiant DL380a Gen11 servers (iLO 6).
pub(super) mod hpe_proliant_dl380a_gen11;

/// Support of Dell PowerEdge R750 servers.
pub(super) mod dell_poweredge_r750;

/// Support of Dell PowerEdge R760 server with Bluefield4 installed.
pub(super) mod dell_poweredge_r760_bf4;

/// Support of Wiwynn GB200 NVL servers.
pub(super) mod wiwynn_gb200_nvl;

/// Rack hardware layouts.
pub(super) mod rack;

/// WIWYNN GB200 NVL72 rack.
pub(super) mod wiwynn_gb200_nvl72_rack;

/// Lenovo GB300 NVL72 rack.
pub(super) mod lenovo_gb300_nvl72_rack;

/// Support of Lenovo GB300 NVL servers.
pub(super) mod lenovo_gb300_nvl;

/// Support of DGX GB300 NVL servers (NVIDIA "GB BMC" host).
pub(super) mod dgx_gb300_nvl;

/// Support of Supermicro (SMC) GB300 NVL servers (Supermicro OpenBMC host).
pub(super) mod supermicro_gb300_nvl;

/// Support of DGX VR NVL servers.
pub(super) mod dgx_vr_nvl;

/// Support of LiteOn Power Shelf.
pub(super) mod liteon_power_shelf;

/// Support of Delta Energy Systems Power Shelf.
pub(super) mod delta_power_shelf;

/// Support of NVIDIA Switch ND5200_LD.
pub(super) mod nvidia_switch_nd5200_ld;

/// Support of NVIDIA Switch N5700_LD.
pub(super) mod nvidia_switch_n5700_ld;

/// Support of NVIDIA DGX H100.
pub(super) mod nvidia_dgx_h100;

/// Common support of GB200 and GB300
pub(super) mod nvidia_gbx00;

/// GB200 CPU/GPU
pub(super) mod nvidia_gb200;

/// GB300 CPU/GPU
pub(super) mod nvidia_gb300;

/// Intel E810 NIC.
pub(super) mod nic_intel_e810;

/// Intel X550 NIC.
pub(super) mod nic_intel_x550;

/// Intel I210 NIC.
pub(super) mod nic_intel_i210;

/// NVIDIA ConnectX-7.
pub(super) mod nic_nvidia_cx7;
