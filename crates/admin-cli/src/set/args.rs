/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
