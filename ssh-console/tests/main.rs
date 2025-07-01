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

use crate::util::{run_baseline_test_environment, should_run_integration_tests};
use api_test_helper::utils::REPO_ROOT;
use util::legacy;

#[allow(dead_code)]
static TENANT_SSH_KEY: &str = include_str!("../legacy/tenant_ssh_key");
static TENANT_SSH_PUBKEY: &str = include_str!("../legacy/tenant_ssh_key.pub");

lazy_static! {
    static ref TENANT_SSH_KEY_PATH: PathBuf = REPO_ROOT.join("ssh-console/legacy/tenant_ssh_key");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_legacy() -> eyre::Result<()> {
    if should_run_integration_tests() {
        legacy::setup().await?;
    }
    let Some(env) = run_baseline_test_environment("ssh_console_test_legacy").await? else {
        return Ok(());
    };

    // Run legacy ssh-console
    let temp = TempDir::new()?;
    let legacy_handle = legacy::run(
        env.test_env.carbide_api_addrs[0].port(),
        &env.mat_handle.machines,
        &temp,
    )
    .await?;

    // Give it some time to start
    tokio::time::sleep(Duration::from_secs(5)).await;

    env.run_baseline_assertions(legacy_handle.addr, "legacy ssh-console")
        .await
}

// Soon:
// #[tokio::test(flavor = "multi_thread")]
// async fn legacy_tests() -> eyre::Result<()> {
//     let Some(env) = run_baseline_test_environment().await? else {
//         return Ok(());
//     };
//
//     // Run new ssh-console
//     let temp = TempDir::new()?;
//     let new_handle = new_ssh_console::run(
//         env.test_env.carbide_api_addrs[0].port(),
//         &env.mat_handle.machines,
//         &temp,
//     )
//         .await?;
//
//     // Give it some time to start
//     tokio::time::sleep(Duration::from_secs(5)).await;
//
//     env.run_baseline_assertions(new_handle.addr, "new ssh-console")
//         .await
// }

#[ctor::ctor]
fn setup_test_logging() {
    api_test_helper::setup_logging()
}
