/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use eyre::WrapErr;

/// ovs-vswitchd is part of HBN. It handles network packets in user-space using DPDK
/// (https://www.dpdk.org/). By default it uses 100% of a CPU core to poll for new packets, never
/// yielding. Here we set it to yield the CPU for up to 100us if it's been idle recently.
/// 100us was recommended by NBU/HBN team.
pub async fn set_vswitchd_yield() -> eyre::Result<()> {
    let mut cmd = tokio::process::Command::new("/usr/bin/ovs-vsctl");
    // table: o
    // record: .
    // column: other_config
    // key: pmd-sleep-max
    // value: 100 nanoseconds
    cmd.arg("set")
        .arg("o")
        .arg(".")
        .arg("other_config:pmd-sleep-max=100")
        .kill_on_drop(true);
    let cmd_str = super::pretty_cmd(cmd.as_std());
    tracing::trace!("set_ovs_vswitchd_yield running: {cmd_str}");

    // It takes less than 1s, so allow up to 5
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output())
        .await
        .wrap_err("Timeout")?
        .wrap_err("Error running command")?;
    if !out.status.success() {
        tracing::error!(
            " STDOUT {cmd_str}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        tracing::error!(
            " STDERR {cmd_str}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("Failed running ovs-vsctl command. Check logs for stdout/stderr.");
    }

    Ok(())
}
