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

use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::machine::MachineId;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(
        help = "The remediation id to query, in case the user wants to see which machines have a specific remediation applied.  Provide both arguments to see all the details for a specific remediation and machine.",
        long
    )]
    pub remediation_id: Option<RemediationId>,
    #[clap(
        help = "The machine id to query, in case the user wants to see which remediations have been applied to a specific box.  Provide both arguments to see all the details for a specific remediation and machine.",
        long
    )]
    pub machine_id: Option<MachineId>,
}
