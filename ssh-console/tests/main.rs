/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::time::Duration;
use temp_dir::TempDir;

mod util;

use crate::util::{BaselineTestAssertion, run_baseline_test_environment};
use api_test_helper::utils::REPO_ROOT;
use util::legacy;
use util::new_ssh_console;

#[allow(dead_code)]
static TENANT_SSH_KEY: &str = include_str!("fixtures/tenant_ssh_key");
static TENANT_SSH_PUBKEY: &str = include_str!("fixtures/tenant_ssh_key.pub");

lazy_static! {
    static ref TENANT_SSH_KEY_PATH: PathBuf =
        REPO_ROOT.join("ssh-console/tests/fixtures/tenant_ssh_key");
    static ref ADMIN_SSH_KEY_PATH: PathBuf =
        REPO_ROOT.join("ssh-console/tests/fixtures/admin_ssh_key");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_legacy() -> eyre::Result<()> {
    if !std::env::var("RUN_SSH_CONSOLE_LEGACY_TESTS").is_ok_and(|s| s == "1") {
        tracing::info!(
            "Skipping running legacy integration tests, as RUN_SSH_CONSOLE_LEGACY_TESTS is not set"
        );
        return Ok(());
    }

    legacy::setup().await?;
    // Only run one test machine, as legacy ssh-console cannot use different SSH ports for each BMC
    let Some(env) = run_baseline_test_environment(1).await? else {
        return Ok(());
    };

    // Run legacy ssh-console
    let temp = TempDir::new()?;
    let handle = legacy::run(&env, &temp).await?;

    // Give it some time to start
    tokio::time::sleep(Duration::from_secs(5)).await;

    env.run_baseline_assertions(
        handle.addr,
        "legacy ssh-console",
        &[
            BaselineTestAssertion::ConnectAsInstanceId,
            // BaselineTestAssertion::ConnectAsMachineId, // Not supported by legacy ssh-console today
        ],
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_new_ssh_console() -> eyre::Result<()> {
    if std::env::var("REPO_ROOT").is_err() {
        tracing::info!("Skipping running ssh-console integration tests, as REPO_ROOT is not set");
        return Ok(());
    }
    let Some(env) = run_baseline_test_environment(2).await? else {
        return Ok(());
    };

    // Run new ssh-console
    let handle = new_ssh_console::spawn(env.mock_api_server.addr.port()).await?;

    env.run_baseline_assertions(
        handle.addr,
        "new-ssh-console",
        &[
            BaselineTestAssertion::ConnectAsInstanceId,
            BaselineTestAssertion::ConnectAsMachineId,
        ],
    )
    .await
}

#[ctor::ctor]
fn setup_test_logging() {
    api_test_helper::setup_logging()
}
