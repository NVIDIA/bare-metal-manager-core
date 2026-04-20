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

use serde::{Deserialize, Serialize};

/// Power action shared across Switch (NVSwitch) and PowerShelf backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerAction {
    On,
    GracefulShutdown,
    ForceOff,
    GracefulRestart,
    ForceRestart,
    AcPowercycle,
}

/// Firmware update lifecycle state shared across Switch and PowerShelf backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirmwareState {
    Unknown,
    Queued,
    InProgress,
    Verifying,
    Completed,
    Failed,
    Cancelled,
}

/// Updatable components of an Switch tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvSwitchComponent {
    Bmc,
    Cpld,
    Bios,
    Nvos,
}

/// Updatable components of a PowerShelf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerShelfComponent {
    Pmc,
    Psu,
}
