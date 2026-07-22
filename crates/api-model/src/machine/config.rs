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
use carbide_uuid::instance_type::InstanceTypeId;
use chrono::{DateTime, Utc};

use crate::machine::Dpf;

/// Operator-set desired state for a machine, mutable via API calls that increment the
/// machine version.
///
/// Corresponds to `MachineConfig` in the forge proto. Fields here are changed via
/// explicit operator API calls (maintenance, instance-type assignment, firmware policy,
/// DPF toggle, SKU assignment).
#[derive(Debug, Clone, Default)]
pub struct MachineConfig {
    /// Override to enable or disable firmware auto-update.
    pub firmware_autoupdate: Option<bool>,

    /// The instance type this machine is associated with, if any.
    pub instance_type_id: Option<InstanceTypeId>,

    /// DPF configuration for this machine (operator-enabled).
    pub dpf: Dpf,

    /// The declared desired hardware SKU (set via the AssignSku API).
    /// Distinct from `MachineStatus::hw_sku`, which reflects the observed match.
    pub hw_sku: Option<String>,

    /// Maintenance reference token set when this machine is placed into maintenance mode.
    pub maintenance_reference: Option<String>,

    /// When maintenance mode began, if active.
    pub maintenance_start_time: Option<DateTime<Utc>>,
}
