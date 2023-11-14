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

use std::{net::SocketAddr, process};

pub fn metrics(metrics_endpoint: SocketAddr) -> eyre::Result<String> {
    let endpoint = format!("http://{metrics_endpoint}/metrics");
    let args = vec![endpoint.clone()];
    // We don't pass the full path to curl here and rely on the fact
    // that `Command` searches the PATH. This makes function signatures tidier.
    let out = process::Command::new("curl").args(args).output()?;
    let response = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        tracing::error!("curl {endpoint} STDOUT: {response}");
        tracing::error!(
            "curl {endpoint} STDERR: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eyre::bail!("curl {endpoint} exit status code {}", out.status);
    }
    Ok(response.to_string())
}

/// Waits for a specific metric line to show up. Returns the metrics
pub async fn wait_for_metric_line(
    metrics_endpoint: SocketAddr,
    expected_line: &str,
) -> eyre::Result<String> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut last_metrics = String::new();

    while start.elapsed() < MAX_WAIT {
        last_metrics = metrics(metrics_endpoint)?;
        if last_metrics.contains(expected_line) {
            return Ok(last_metrics);
        }

        tracing::info!("Waiting for metric line");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    eyre::bail!(
        "Even after {MAX_WAIT:?} time, Metric line {expected_line} was not visible.\n
        Last metrics: {last_metrics}"
    );
}

pub fn assert_metric_line(metrics: &str, expected: &str) {
    assert!(
        metrics.contains(expected),
        "Expected \"{expected}\" in Metrics/nActual metrics are:\n{metrics}"
    );
}

pub fn assert_not_metric_line(metrics: &str, expected: &str) {
    assert!(
        !metrics.contains(expected),
        "Expected missing \"{expected}\" in Metrics/nActual metrics are:\n{metrics}"
    );
}
