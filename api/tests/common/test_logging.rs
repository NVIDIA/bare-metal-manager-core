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

use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter::EnvFilter, fmt::TestWriter, prelude::*};

/// Initializes the `tracing` logging system for the use in integration tests
pub fn init() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("sqlx=warn".parse().unwrap())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    // Note: `TestWriter` is required to use the standard behavior of Rust unit tests:
    // - Successful tests won't show output unless forced by the `--nocapture` CLI argument
    // - Failing tests will have their output printed
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_writer(TestWriter::new),
        )
        .with(env_filter)
        .init();
}
