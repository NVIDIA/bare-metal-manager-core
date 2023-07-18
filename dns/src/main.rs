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
use clap::CommandFactory;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

mod cfg;
mod dns;

#[tokio::main]
async fn main() -> Result<(), eyre::Report> {
    let config = Options::load();
    if config.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("hyper=warn".parse()?)
        .add_directive("h2=warn".parse()?);
    tracing_subscriber::registry()
        .with(fmt::Layer::default().compact())
        .with(env_filter)
        .try_init()?;

    let sub_cmd = match &config.sub_cmd {
        None => {
            return Ok(Options::command().print_long_help()?);
        }
        Some(s) => s,
    };
    match sub_cmd {
        Command::Run(ref config) => dns::DnsServer::run(config).await?,
    }

    Ok(())
}
