/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::Duration;

use super::rpc;
use crate::cfg::carbide_options::MachineQuery;
use ::rpc::{forge::get_redfish_job_state_response::RedfishJobState, forge_tls_client::ApiConfig};
use utils::admin_cli::CarbideCliResult;

async fn get_redfish_job_state(
    query: MachineQuery,
    jid: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<RedfishJobState> {
    Ok(rpc::get_redfish_job_state(query, jid, api_config)
        .await?
        .job_state())
}

async fn poll_redfish_job(
    query: MachineQuery,
    jid: String,
    expected_state: RedfishJobState,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    tracing::info!("polling redfish job {jid} to reach an expected state of {expected_state:#?}");
    const SLEEP_TIME: Duration = Duration::from_secs(5);
    // 30 minutes in seconds
    const MAX_WAIT_TIME: Duration = Duration::from_secs(1800);

    let mut i = 0;
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > MAX_WAIT_TIME {
            return Err(crate::CarbideCliError::GenericError(format!(
                "redfish job {jid} did not reach {expected_state:#?} after {}s. Exiting",
                MAX_WAIT_TIME.as_secs()
            )));
        }

        let state = get_redfish_job_state(query.clone(), jid.clone(), api_config).await?;
        if state == expected_state {
            println!("successfully found redfish job {jid} at {state:#?}");
            return Ok(());
        }

        if state == RedfishJobState::CompletedWithErrors {
            return Err(crate::CarbideCliError::GenericError(format!(
                "redfish job {jid} completed with errors"
            )));
        }

        i += 1;
        if i % 10 == 0 {
            println!(
                "job {jid} has a current state of {state:#?}; waiting since {start:#?} for job to reach an expected state of {expected_state:#?}",
            );
        }
        tokio::time::sleep(SLEEP_TIME).await;
    }
}

pub async fn set_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let jid = rpc::set_host_uefi_password(query.clone(), api_config)
        .await?
        .job_id;

    if jid.is_some() {
        // Wait for job to be scheduled,
        poll_redfish_job(
            query.clone(),
            jid.clone().unwrap_or_default(),
            RedfishJobState::Scheduled,
            api_config,
        )
        .await?;
    }

    rpc::force_reboot_machine(query.clone(), api_config).await?;
    if jid.is_some() {
        // Wait for job to complete,
        poll_redfish_job(
            query.clone(),
            jid.clone().unwrap_or_default(),
            RedfishJobState::Completed,
            api_config,
        )
        .await?;
    }

    println!("successfully set UEFI password for host {query:#?}");
    Ok(())
}

pub async fn clear_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let job_id = rpc::clear_host_uefi_password(query.clone(), api_config)
        .await?
        .job_id;
    rpc::force_reboot_machine(query.clone(), api_config).await?;
    if job_id.is_some() {
        // Wait for job to complete,
        poll_redfish_job(
            query.clone(),
            job_id.unwrap_or_default(),
            RedfishJobState::Completed,
            api_config,
        )
        .await?;
    }

    println!("successfully cleared UEFI password for host {query:#?}");

    Ok(())
}
