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

use clap::Parser;
use clap::builder::BoolishValueParser;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Set RUST_LOG")]
    LogFilter(LogFilterOptions),
    #[clap(about = "Set create_machines")]
    CreateMachines(CreateMachinesOptions),
    #[clap(about = "Set bmc_proxy")]
    BmcProxy(BmcProxyOptions),
    #[clap(
        about = "Configure whether trace/span information is sent to an OTLP endpoint like Tempo"
    )]
    TracingEnabled {
        #[arg(num_args = 1, value_parser = BoolishValueParser::new(), action = clap::ArgAction::Set, value_name = "true|false")]
        value: bool,
    },
}

#[derive(Parser, Debug, Clone)]
pub struct LogFilterOptions {
    #[clap(short, long, help = "Set server's RUST_LOG.")]
    pub filter: String,
    #[clap(
        long,
        default_value("1h"),
        help = "Revert to startup RUST_LOG after this much time, friendly format e.g. '1h', '3min', https://docs.rs/duration-str/latest/duration_str/"
    )]
    pub expiry: String,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateMachinesOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer create_machines?")]
    pub enabled: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct BmcProxyOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer bmc_proxy")]
    pub enabled: bool,
    #[clap(long, action = clap::ArgAction::Set, help = "host:port string use as a proxy for talking to BMC's")]
    pub proxy: Option<String>,
}
