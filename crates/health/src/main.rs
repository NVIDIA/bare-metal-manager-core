/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Redfish models have a very high recursion (Root->Chassis->Storage->Drive->Metric->etc)
// This param is required to make it compile while using nv-redfish
#![recursion_limit = "256"]

use carbide_health::{Config, HealthError};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), HealthError> {
    let config_path = std::env::args().nth(1).map(std::path::PathBuf::from);
    let config = Config::load(config_path.as_deref()).map_err(HealthError::GenericError)?;

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(logfmt::layer())
        .with(env_filter)
        .init();

    tracing::info!(
        version = carbide_version::v!(build_version),
        config = ?config,
        "Started carbide-hw-health"
    );

    carbide_health::run_service(config).await?;

    tracing::info!(
        version = carbide_version::v!(build_version),
        "Stopped carbide-hw-health"
    );

    Ok(())
}
