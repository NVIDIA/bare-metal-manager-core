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

use model::machine::HostHealthConfig;
use serde::{Deserialize, Serialize};

pub mod bom_validation;
pub mod controller;
pub mod firmware_global;
pub mod machine_validation;
pub mod power_manager;

pub use bom_validation::BomValidationConfig;
pub use controller::MachineStateControllerConfig;
pub use firmware_global::FirmwareGlobal;
pub use machine_validation::MachineValidationConfig;
pub use power_manager::PowerManagerOptions;

pub struct MachineStateHandlerSiteConfig {
    pub firmware_global: FirmwareGlobal,
    pub machine_state_controller: MachineStateControllerConfig,
    pub host_health: HostHealthConfig,

    pub selected_profile: libredfish::BiosProfileType,
    pub bios_profiles: libredfish::BiosProfileVendor,
    pub oem_manager_profiles: libredfish::BiosProfileVendor,

    pub dpa_enabled: bool,
    pub dpf_enabled: bool,
    pub spdm_enabled: bool,

    pub dpu_enable_secure_boot: bool,
}

/// A UTC time window defined by a start and end timestamp.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TimePeriod {
    /// Start of the time window (UTC).
    pub start: chrono::DateTime<chrono::Utc>,
    /// End of the time window (UTC).
    pub end: chrono::DateTime<chrono::Utc>,
}
