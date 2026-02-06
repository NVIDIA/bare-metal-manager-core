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
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[clap(name = "forge-dhcp-server")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct Args {
    #[arg(long, help = "Interface name where to bind this server.")]
    pub interfaces: Vec<String>,

    #[arg(long, help = "DHCP Config file path.")]
    pub dhcp_config: String,

    #[arg(long, help = "DPU Agent provided input file path for IP selection.")]
    pub host_config: Option<String>,

    #[arg(short, long, value_enum, default_value_t=ServerMode::Dpu)]
    pub mode: ServerMode,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServerMode {
    Dpu,
    Controller,
}

impl Args {
    pub fn load() -> Self {
        Self::parse()
    }
}
