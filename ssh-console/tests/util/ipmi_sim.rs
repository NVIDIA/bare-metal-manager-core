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

use crate::util::log_stdout_and_stderr;
use api_test_helper::utils::REPO_ROOT;
use eyre::Context;
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::process::Stdio;

lazy_static! {
    static ref IPMI_SCRIPTS_DIR: PathBuf = REPO_ROOT.join("dev/ipmi").canonicalize().unwrap();
}

pub struct IpmiSimHandle {
    _ipmi_sim: tokio::process::Child,
    _serial_console: tokio::process::Child,
}

pub async fn run() -> eyre::Result<IpmiSimHandle> {
    // Run a simple python echo server to pretend it's a serial console
    let serial_console_process = run_mock_serial_console().await?;

    // Then run ipmi_sim
    let bin = IPMI_SCRIPTS_DIR.join("run_ipmi_sim.sh");
    tracing::info!("Launching run_ipmi_sim.sh at {}", bin.to_string_lossy());
    let mut process = tokio::process::Command::new(&bin)
        .current_dir(IPMI_SCRIPTS_DIR.as_path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context(format!(
            "failed to spawn ipmi_sim.sh at {}",
            bin.to_string_lossy()
        ))?;
    log_stdout_and_stderr(&mut process, "run_ipmi_sim.sh");

    Ok(IpmiSimHandle {
        _ipmi_sim: process,
        _serial_console: serial_console_process,
    })
}

pub async fn run_mock_serial_console() -> eyre::Result<tokio::process::Child> {
    let bin = IPMI_SCRIPTS_DIR.join("mock_serial_console.py");
    tracing::info!(
        "Launching mock_serial_console.py at {}",
        bin.to_string_lossy()
    );
    let mut process = tokio::process::Command::new(&bin)
        .current_dir(IPMI_SCRIPTS_DIR.as_path())
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context(format!(
            "failed to spawn mock_serial_console.py at {}",
            bin.to_string_lossy()
        ))?;
    log_stdout_and_stderr(&mut process, "mock_serial_console.py");
    Ok(process)
}
