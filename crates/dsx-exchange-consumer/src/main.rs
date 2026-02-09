/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_dsx_exchange_consumer::{Config, DsxConsumerError};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[tokio::main]
async fn main() -> Result<(), DsxConsumerError> {
    let config_path = std::env::args().nth(1).map(std::path::PathBuf::from);
    let config = Config::load(config_path.as_deref()).map_err(DsxConsumerError::Config)?;

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(logfmt::layer().with_filter(env_filter))
        .try_init()
        .map_err(|e| DsxConsumerError::Config(e.to_string()))?;

    tracing::info!(
        version = carbide_version::v!(build_version),
        config = ?config,
        "Started carbide-dsx-exchange-consumer"
    );

    carbide_dsx_exchange_consumer::run_service(config).await?;

    tracing::info!(
        version = carbide_version::v!(build_version),
        "Stopped carbide-dsx-exchange-consumer"
    );

    Ok(())
}
