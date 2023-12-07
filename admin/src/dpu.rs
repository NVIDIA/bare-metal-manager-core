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
use prettytable::{row, Table};

use super::{rpc, CarbideCliResult};
use crate::{cfg::carbide_options::AgentUpgradePolicyChoice, Config};

pub async fn trigger_reprovisioning(
    id: String,
    set: bool,
    update_firmware: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    rpc::trigger_dpu_reprovisioning(id, set, update_firmware, api_config).await
}

pub async fn list_dpus_pending(api_config: Config) -> CarbideCliResult<()> {
    let response = rpc::list_dpu_pending_for_reprovisioning(api_config).await?;
    print_pending_dpus(response);
    Ok(())
}

fn print_pending_dpus(dpus: ::rpc::forge::DpuReprovisioningListResponse) {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "State",
        "Initiator",
        "Requested At",
        "Initiated At",
        "Update Firmware",
        "User Approved"
    ]);

    for dpu in dpus.dpus {
        let user_approval = if dpu.user_approval_received {
            "Yes"
        } else if dpu.state.contains("Assigned") {
            "No"
        } else {
            "NA"
        };
        table.add_row(row![
            dpu.id.unwrap_or_default().to_string(),
            dpu.state,
            dpu.initiator,
            dpu.requested_at.unwrap_or_default(),
            dpu.initiated_at
                .map(|x| x.to_string())
                .unwrap_or_else(|| "Not Started".to_string()),
            dpu.update_firmware,
            user_approval
        ]);
    }

    table.printstd();
}

pub async fn handle_agent_upgrade_policy(
    api_config: Config,
    action: Option<::rpc::forge::AgentUpgradePolicy>,
) -> CarbideCliResult<()> {
    match action {
        None => {
            let resp = rpc::dpu_agent_upgrade_policy_action(&api_config, None).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!("{policy}");
        }
        Some(choice) => {
            let resp = rpc::dpu_agent_upgrade_policy_action(&api_config, Some(choice)).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!(
                "Policy is now: {policy}. Update succeeded? {}.",
                resp.did_change,
            );
        }
    }
    Ok(())
}
