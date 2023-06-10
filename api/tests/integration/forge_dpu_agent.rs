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

use std::{path, process};

pub fn run(
    root_dir: &path::Path,
    cfg_path: &str,
    hbn_root: &path::Path,
    dpu_machine_id: &str,
) -> eyre::Result<()> {
    let out = process::Command::new(root_dir.join("target/debug/forge-dpu-agent"))
        .arg("--config-path")
        .arg(cfg_path)
        .arg("netconf")
        .arg("--dpu-machine-id")
        .arg(dpu_machine_id)
        .arg("--chroot")
        .arg(&hbn_root.display().to_string())
        .arg("--skip-reload")
        .output()?;
    let response = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        tracing::error!("forge-dpu-agent STDOUT: {response}");
        tracing::error!(
            "forge-dpu-agent STDERR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("forge-dpu-agent exit status code {}", out.status);
    }

    tracing::debug!("{response}");
    Ok(())
}
