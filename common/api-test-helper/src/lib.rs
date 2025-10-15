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

pub mod api_server;
pub mod domain;
pub mod grpcurl;
pub mod instance;
pub mod machine;
pub mod machine_a_tron;
pub mod metrics;
pub mod subnet;
pub mod tenant;
pub mod utils;
pub mod vault;
pub mod vpc;

pub use utils::IntegrationTestEnvironment;

pub fn setup_logging() {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::fmt::TestWriter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::util::SubscriberInitExt;

    if let Err(e) = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_writer(TestWriter::new),
        )
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("sqlx=warn".parse().unwrap())
                .add_directive("tower=warn".parse().unwrap())
                .add_directive("rustify=off".parse().unwrap())
                .add_directive("rustls=warn".parse().unwrap())
                .add_directive("hyper=warn".parse().unwrap())
                .add_directive("h2=warn".parse().unwrap())
                // Silence permissive mode related messages
                .add_directive("carbide::auth=error".parse().unwrap()),
        )
        .try_init()
    {
        // Note: Resist the temptation to ignore this error. We really should only have one place in
        // the test binary that initializes logging.
        panic!(
            "Failed to initialize trace logging for api-test tests. It's possible some earlier \
            code path has already set a global default log subscriber: {e}"
        );
    }
}
