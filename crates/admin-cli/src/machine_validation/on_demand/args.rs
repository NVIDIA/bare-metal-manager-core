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

#[derive(Parser, Debug)]
pub enum Args {
    #[clap(about = "Start on demand machine validation")]
    Start(OnDemandOptions),
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct OnDemandOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(short, long, help = "Machine id for start validation")]
    pub machine: MachineId,

    #[clap(long, help = "Results history")]
    pub tags: Option<Vec<String>>,

    #[clap(long, help = "Allowed tests")]
    pub allowed_tests: Option<Vec<String>>,

    #[clap(long, default_value = "false", help = "Run not verfified tests")]
    pub run_unverfied_tests: bool,

    #[clap(long, help = "Contexts")]
    pub contexts: Option<Vec<String>>,
}
