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

use std::{fs, io, path, process};

const DPU_CONFIG_FILE: &str = "/tmp/forge-dpu-agent-sim-config.toml";
const DPU_CONFIG: &str = r#"
[forge-system]
api-server = "https://127.0.0.1:1079"
pxe-server = "http://127.0.0.1:8080"
root-ca = "$ROOT_DIR/dev/certs/forge_root.pem"

[machine]
interface-id = "$MACHINE_INTERFACE_ID"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.example.com"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = true
"#;

// Must be called before 'run'
pub fn write_config(
    root_dir: &path::Path,
    machine_interface_id: &str,
    hbn_root: &path::Path,
) -> io::Result<()> {
    let cfg = DPU_CONFIG
        .replace("$MACHINE_INTERFACE_ID", machine_interface_id)
        .replace("$HBN_ROOT", &hbn_root.display().to_string())
        .replace("$ROOT_DIR", &root_dir.display().to_string());
    fs::write(DPU_CONFIG_FILE, cfg)
}

pub fn run(forge_dpu_agent: &path::Path, dpu_machine_id: &str) -> eyre::Result<()> {
    let out = process::Command::new(forge_dpu_agent)
        .arg("--config-path")
        .arg(DPU_CONFIG_FILE)
        .arg("netconf")
        .arg("--dpu-machine-id")
        .arg(dpu_machine_id)
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
