/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use ::rpc::admin_cli::CarbideCliResult;

use super::args::AgentUpgradePolicyChoice;
use crate::rpc::ApiClient;

pub async fn agent_upgrade_policy(
    api_client: &ApiClient,
    set: Option<AgentUpgradePolicyChoice>,
) -> CarbideCliResult<()> {
    let rpc_choice = set.map(|cmd_line_policy| match cmd_line_policy {
        AgentUpgradePolicyChoice::Off => rpc::forge::AgentUpgradePolicy::Off,
        AgentUpgradePolicyChoice::UpOnly => rpc::forge::AgentUpgradePolicy::UpOnly,
        AgentUpgradePolicyChoice::UpDown => rpc::forge::AgentUpgradePolicy::UpDown,
    });
    handle_agent_upgrade_policy(api_client, rpc_choice).await
}

pub async fn handle_agent_upgrade_policy(
    api_client: &ApiClient,
    action: Option<::rpc::forge::AgentUpgradePolicy>,
) -> CarbideCliResult<()> {
    match action {
        None => {
            let resp = api_client
                .0
                .dpu_agent_upgrade_policy_action(rpc::forge::DpuAgentUpgradePolicyRequest {
                    new_policy: None,
                })
                .await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!("{policy}");
        }
        Some(choice) => {
            let resp = api_client.0.dpu_agent_upgrade_policy_action(choice).await?;
            let policy: AgentUpgradePolicyChoice = resp.active_policy.into();
            tracing::info!(
                "Policy is now: {policy}. Update succeeded? {}.",
                resp.did_change,
            );
        }
    }
    Ok(())
}
