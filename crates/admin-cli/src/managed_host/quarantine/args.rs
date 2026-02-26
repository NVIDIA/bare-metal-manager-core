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

use carbide_uuid::machine::MachineId;
use clap::Parser;

/// Enable or disable quarantine mode on a managed host.
#[derive(Parser, Debug)]
pub enum Args {
    /// Put this machine into quarantine. Prevents any network access on the host machine.
    On(QuarantineOn),
    /// Take this machine out of quarantine
    Off(QuarantineOff),
}

#[derive(Parser, Debug)]
pub struct QuarantineOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: MachineId,

    #[clap(
        long,
        visible_alias = "reason",
        required(true),
        help = "Reason for quarantining this host"
    )]
    pub reason: String,
}

#[derive(Parser, Debug)]
pub struct QuarantineOff {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: MachineId,
}
