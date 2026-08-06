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

use crate::{
    Accounts, Attestation, Bios, BmcControl, BootOrder, Capability, CapabilitySelection, Console,
    Dpu, Firmware, Lockdown, Power, SecureBoot, Storage,
};

/// Object-safe lookup of selected compiled-in capability implementations.
///
/// Implementations own each standard implementation and resolve
/// [`CapabilitySelection::Standard`] without runtime branching.
pub trait DriverRegistry: Send + Sync {
    fn power(&self, selection: &CapabilitySelection) -> Option<&dyn Power>;
    fn bmc_control(&self, selection: &CapabilitySelection) -> Option<&dyn BmcControl>;
    fn bios(&self, selection: &CapabilitySelection) -> Option<&dyn Bios>;
    fn boot_order(&self, selection: &CapabilitySelection) -> Option<&dyn BootOrder>;
    fn secure_boot(&self, selection: &CapabilitySelection) -> Option<&dyn SecureBoot>;
    fn lockdown(&self, selection: &CapabilitySelection) -> Option<&dyn Lockdown>;
    fn accounts(&self, selection: &CapabilitySelection) -> Option<&dyn Accounts>;
    fn firmware(&self, selection: &CapabilitySelection) -> Option<&dyn Firmware>;
    fn storage(&self, selection: &CapabilitySelection) -> Option<&dyn Storage>;
    fn dpu(&self, selection: &CapabilitySelection) -> Option<&dyn Dpu>;
    fn attestation(&self, selection: &CapabilitySelection) -> Option<&dyn Attestation>;
    fn console(&self, selection: &CapabilitySelection) -> Option<&dyn Console>;

    fn supports(&self, capability: Capability, selection: &CapabilitySelection) -> bool {
        match capability {
            Capability::Power => self.power(selection).is_some(),
            Capability::BmcControl => self.bmc_control(selection).is_some(),
            Capability::Bios => self.bios(selection).is_some(),
            Capability::BootOrder => self.boot_order(selection).is_some(),
            Capability::SecureBoot => self.secure_boot(selection).is_some(),
            Capability::Lockdown => self.lockdown(selection).is_some(),
            Capability::Accounts => self.accounts(selection).is_some(),
            Capability::Firmware => self.firmware(selection).is_some(),
            Capability::Storage => self.storage(selection).is_some(),
            Capability::Dpu => self.dpu(selection).is_some(),
            Capability::Attestation => self.attestation(selection).is_some(),
            Capability::Console => self.console(selection).is_some(),
        }
    }
}
