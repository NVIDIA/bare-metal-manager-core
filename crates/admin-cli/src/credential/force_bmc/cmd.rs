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

use super::args::{ForceClear, ForceSet};
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

/// A human-readable description of whichever BMC identifier(s) the operator
/// supplied, for the confirmation message. `machine_id` and `switch_id` are
/// mutually exclusive (enforced by clap), so at most one device id is set.
fn describe_target(
    machine_id: Option<String>,
    switch_id: Option<String>,
    bmc_mac: Option<String>,
) -> String {
    match (machine_id, switch_id, bmc_mac) {
        (Some(id), _, Some(mac)) => format!("machine {id} (BMC {mac})"),
        (Some(id), _, None) => format!("machine {id}"),
        (None, Some(id), Some(mac)) => format!("switch {id} (BMC {mac})"),
        (None, Some(id), None) => format!("switch {id}"),
        (None, None, Some(mac)) => format!("BMC {mac}"),
        (None, None, None) => "the requested BMC".to_string(),
    }
}

pub async fn set(data: ForceSet, api_client: &ApiClient) -> CarbideCliResult<()> {
    let target = describe_target(
        data.id.map(|id| id.to_string()),
        data.switch_id.map(|id| id.to_string()),
        data.bmc_mac.map(|mac| mac.to_string()),
    );
    api_client.0.trigger_bmc_credential_rotation(data).await?;
    println!(
        "Requested force-converge of {target}. The state controller rotates it on its next \
         sweep (bypassing backoff); confirm this device converged with \
         `credential rotation-status --type=bmc --mac-address <bmc-mac>` (the per-device query, \
         not the site-wide view).",
    );
    Ok(())
}

pub async fn clear(data: ForceClear, api_client: &ApiClient) -> CarbideCliResult<()> {
    let target = describe_target(
        data.id.map(|id| id.to_string()),
        data.switch_id.map(|id| id.to_string()),
        data.bmc_mac.map(|mac| mac.to_string()),
    );
    api_client.0.trigger_bmc_credential_rotation(data).await?;
    println!("Cleared any pending BMC force-converge request for {target}.");
    Ok(())
}
