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
use eyre::Context;
use futures_util::FutureExt;
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::time::Duration;
use temp_dir::TempDir;

mod util;

use crate::util::{BaselineTestAssertion, MockBmcType, run_baseline_test_environment};
use api_test_helper::utils::REPO_ROOT;
use ssh_console::shutdown_handle::ShutdownHandle;
use util::{legacy, new_ssh_console};

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
async fn test_legacy_ssh() -> eyre::Result<()> {
    if !std::env::var("RUN_SSH_CONSOLE_LEGACY_TESTS").is_ok_and(|s| s == "1") {
        tracing::info!(
            "Skipping running legacy integration tests, as RUN_SSH_CONSOLE_LEGACY_TESTS is not set"
        );
        return Ok(());
    }

    legacy::setup().await?;
    // Only run one test machine, as legacy ssh-console cannot use different SSH ports for each BMC
    let Some(env) = run_baseline_test_environment(vec![MockBmcType::Ssh]).await? else {
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
        || None,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_legacy_ipmi() -> eyre::Result<()> {
    if !std::env::var("RUN_SSH_CONSOLE_LEGACY_TESTS").is_ok_and(|s| s == "1") {
        tracing::info!(
            "Skipping running legacy integration tests, as RUN_SSH_CONSOLE_LEGACY_TESTS is not set"
        );
        return Ok(());
    }

    legacy::setup().await?;
    // Only run one test machine, as legacy ssh-console cannot use different SSH ports for each BMC
    let Some(env) = run_baseline_test_environment(vec![MockBmcType::Ipmi]).await? else {
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
        || None,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_new_ssh_console() -> eyre::Result<()> {
    if std::env::var("REPO_ROOT").is_err() {
        tracing::info!("Skipping running ssh-console integration tests, as REPO_ROOT is not set");
        return Ok(());
    }
    let Some(env) =
        run_baseline_test_environment(vec![MockBmcType::Ipmi, MockBmcType::Ssh]).await?
    else {
        return Ok(());
    };

    // Run new ssh-console
    let handle = new_ssh_console::spawn(env.mock_api_server.addr.port()).await?;

    // Run the same assertions we do with legacy ssh-console
    env.run_baseline_assertions(
        handle.addr,
        "new-ssh-console",
        &[
            BaselineTestAssertion::ConnectAsInstanceId,
            BaselineTestAssertion::ConnectAsMachineId,
        ],
        || Some(new_ssh_console::get_metrics(handle.metrics_address).boxed()),
        true,
    )
    .await?;

    // Now test things specific to the new ssh-console

    // Shut down ssh-console now so we can assert on final log lines (and make sure it shuts down
    // properly.)
    handle.spawn_handle.shutdown_and_wait().await;

    let logs_path = handle.logs_dir.path();

    assert!(
        logs_path.exists(),
        "logs were not created for new ssh-console"
    );

    for mock_host in env.mock_hosts.iter() {
        let log_path = logs_path.join(format!("{}_{}.log", mock_host.machine_id, mock_host.bmc_ip));
        assert!(
            log_path.exists(),
            "did not see any logs at {}",
            log_path.display()
        );

        let logs = std::fs::read_to_string(&log_path)
            .with_context(|| format!("error reading log file at {}", log_path.display()))?;

        // Find "ssh-console connected" lines
        let (connection_lines, other_lines) = logs
            .lines()
            .partition::<Vec<_>, _>(|l| l.starts_with("--- ssh-console connected at "));

        // Find the "ssh-console disconnected at" line
        let (disconnection_lines, other_lines) = other_lines
            .into_iter()
            .partition::<Vec<_>, _>(|l| l.starts_with("--- ssh-console disconnected at "));

        assert!(
            !connection_lines.is_empty(),
            "{} does not contain at least one line saying `--- ssh-console connected at`:\n{}",
            log_path.display(),
            logs
        );

        assert!(
            !other_lines.is_empty(),
            "{} does not contain any lines except connection status lines:\n{}",
            log_path.display(),
            logs
        );

        assert_eq!(
            disconnection_lines.len(),
            1,
            "{} does not contain expected disconnected line:\n{}",
            log_path.display(),
            logs
        );

        assert!(
            logs.lines()
                .last()
                .is_some_and(|l| l == disconnection_lines[0]),
            "{} did not have the shutdown line as its last line:\n{}",
            log_path.display(),
            logs
        );
    }

    Ok(())
}

#[ctor::ctor]
fn setup_test_logging() {
    api_test_helper::setup_logging()
}
