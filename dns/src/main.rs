/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use cfg::{Command, Options};
use log::LevelFilter;

mod cfg;
mod dns;

#[tokio::main]
async fn main() -> Result<(), eyre::Report> {
    let config = Options::load();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Debug
            }
            _ => {
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Trace
            }
        })
        .init();

    match config.sub_cmd {
        Command::Run(ref config) => dns::DnsServer::run(config).await?,
    }

    Ok(())
}
