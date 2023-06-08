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

//! forge-host-support is a library that is used by applications that run on
//! Forge managed hosts

use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

pub mod agent_config;
pub mod cmd;
pub mod hardware_enumeration;
pub mod registration;

/// Initialize logging output to STDOUT.
/// Use `export RUST_LOG=trace|debug|info|warn|error` to change log level.
pub fn init_logging() -> Result<(), eyre::Report> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("hyper=warn".parse()?)
        .add_directive("h2=warn".parse()?);
    let stdout_formatter = fmt::Layer::default()
        .compact()
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false);
    tracing_subscriber::registry()
        .with(stdout_formatter)
        .with(env_filter)
        .try_init()?;
    Ok(())
}
