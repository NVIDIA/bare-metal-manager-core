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
use std::sync::Arc;

use crate::injection::InjectionStore;
use crate::redfish;
use crate::redfish::account_service::AccountServiceState;
use crate::redfish::chassis::ChassisState;
use crate::redfish::computer_system::SystemState;
use crate::redfish::manager::ManagerState;
use crate::redfish::session_service::SessionServiceState;
use crate::redfish::update_service::UpdateServiceState;

#[derive(Clone)]
pub struct BmcState {
    pub bmc_vendor: redfish::oem::BmcVendor,
    pub bmc_product: Option<&'static str>,
    pub bmc_redfish_version: &'static str,
    pub oem_state: redfish::oem::State,
    pub manager: Arc<ManagerState>,
    pub system_state: Arc<SystemState>,
    pub chassis_state: Arc<ChassisState>,
    pub update_service_state: Arc<UpdateServiceState>,
    pub account_service_state: Arc<AccountServiceState>,
    pub session_service_state: Arc<SessionServiceState>,
    pub injection: Arc<InjectionStore>,
    pub callbacks: Option<Arc<dyn crate::Callbacks>>,
    /// Whether this BMC advertises and serves the `/redfish/v1/Systems`
    /// collection. Delta power shelves expose no `ComputerSystem` collection,
    /// so the service root omits the `Systems` link and the collection endpoint
    /// returns 404.
    pub exposes_computer_systems: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum BmcEvent {
    PowerOn,
    BootCompleted,
}

impl BmcState {
    pub fn on_event(&self, event: &BmcEvent) {
        match event {
            BmcEvent::PowerOn => {
                self.complete_all_bios_jobs();
                self.apply_pending_bluefield_mode();
            }
            BmcEvent::BootCompleted => {
                self.system_state.on_boot_completed();
            }
        }
    }

    pub fn complete_all_bios_jobs(&self) {
        if let redfish::oem::State::DellIdrac(v) = &self.oem_state {
            v.complete_all_bios_jobs()
        }
    }

    /// Apply a BlueField's queued `Mode.Set` (the BF-3 OEM DPU/NIC mode flip),
    /// if any. Real hardware picks up the staged mode only after a power cycle,
    /// so this runs on `PowerOn`.
    fn apply_pending_bluefield_mode(&self) {
        if let redfish::oem::State::NvidiaBluefield(v) = &self.oem_state {
            v.apply_pending_mode();
        }
    }

    /// The BlueField's current NIC-mode flag, or `None` for a BMC that does not
    /// mock a BlueField (e.g. the host iDRAC). Lets machine-a-tron observe a DPU
    /// that flipped to NIC mode on a power cycle and converge to NIC behavior.
    pub fn bluefield_nic_mode(&self) -> Option<bool> {
        match &self.oem_state {
            redfish::oem::State::NvidiaBluefield(v) => Some(v.nic_mode()),
            _ => None,
        }
    }
}
