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
use clap::{ArgGroup, Parser, ValueEnum};

#[derive(Parser, Debug)]
pub enum Args {
    #[clap(about = "List the health reports overrides")]
    Show { machine_id: MachineId },
    #[clap(about = "Insert a health report override")]
    Add(HealthAddOptions),
    #[clap(about = "Print a empty health override template, which user can modify and use")]
    PrintEmptyTemplate,
    #[clap(about = "Remove a health report override")]
    Remove {
        machine_id: MachineId,
        report_source: String,
    },
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("override_health").required(true).args(&["health_report", "template"])))]
pub struct HealthAddOptions {
    pub machine_id: MachineId,
    #[clap(long, help = "New health report as json")]
    pub health_report: Option<String>,
    #[clap(
        long,
        help = "Predefined Template name. Use host-update for DPU Reprovision"
    )]
    pub template: Option<HealthOverrideTemplates>,
    #[clap(long, help = "Message to be filled in template.")]
    pub message: Option<String>,
    #[clap(long, help = "Replace all other health reports with this override")]
    pub replace: bool,
    #[clap(long, help = "Print the template that is going to be send to carbide")]
    pub print_only: bool,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum HealthOverrideTemplates {
    HostUpdate,
    InternalMaintenance,
    OutForRepair,
    Degraded,
    Validation,
    SuppressExternalAlerting,
    MarkHealthy,
    StopRebootForAutomaticRecoveryFromStateMachine,
    TenantReportedIssue,
    RequestRepair,
}
