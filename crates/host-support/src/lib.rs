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

//! carbide-host-support is a library that is used by applications that run on
//! carbide managed hosts

use std::sync::Once;

use tracing::metadata::LevelFilter;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

pub mod agent_config;
pub mod dpa_cmds;
#[cfg(feature = "linux-build")]
pub mod hardware_enumeration;
pub mod registration;

static LOG_SETUP: Once = Once::new();

/// Initialize global logging output to STDOUT. Applies to all threads.
/// Use `export RUST_LOG=trace|debug|info|warn|error` to change log level.
pub fn init_logging() -> eyre::Result<()> {
    LOG_SETUP.call_once(|| {
        subscriber()
            .try_init()
            .expect("tracing_subscriber setup failed");
    });
    Ok(())
}

// A logging subscriber for use on the current thread.
// Usually you want `init_logging()` instead.
//
// Usage: `let guard = subscriber().set_default()`
// Subscriber is unregistered when guard is dropped.
pub fn subscriber() -> impl SubscriberInitExt {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("sqlx=info".parse().unwrap())
        .add_directive("tokio_util::codec=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        .add_directive("hickory_resolver::error=info".parse().unwrap())
        .add_directive("hickory_proto::xfer=info".parse().unwrap())
        .add_directive("hickory_resolver::name_server=info".parse().unwrap())
        .add_directive("hickory_proto=info".parse().unwrap())
        .add_directive("netlink_proto=warn".parse().unwrap());
    let stdout_formatter = logfmt::layer();
    Box::new(tracing_subscriber::registry().with(stdout_formatter.with_filter(env_filter)))
}
