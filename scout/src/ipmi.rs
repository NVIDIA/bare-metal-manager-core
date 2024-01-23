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

use std::time::Instant;

use scout::{CarbideClientError, CarbideClientResult};
use tokio::time::{sleep, Duration};
use utils::cmd::Cmd;

pub async fn wait_until_ipmi_is_ready() -> CarbideClientResult<()> {
    let now = Instant::now();
    const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 12);
    const RETRY_TIME: Duration = Duration::from_secs(5);

    while now.elapsed() <= MAX_TIMEOUT {
        if Cmd::new("ipmitool")
            .args(vec!["user", "list", "1"])
            .output()
            .is_ok()
        {
            tracing::info!("ipmitool ready after {} seconds", now.elapsed().as_secs());
            return Ok(());
        } else {
            tracing::debug!(
                "still waiting for ipmitool after {} seconds",
                now.elapsed().as_secs()
            );
            sleep(RETRY_TIME).await;
        }
    }
    //
    // Reached here, means MAX_TIMEOUT passed and yet ipmitool command is still failing.
    let err_log = format!(
        "Max timeout ({} seconds) is elapsed and still ipmitool is failed.",
        MAX_TIMEOUT.as_secs(),
    );
    tracing::error!(err_log);
    Err(CarbideClientError::GenericError(err_log))
}
