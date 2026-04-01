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

use std::sync::Arc;

use eyre::eyre;
use forge_dpu_agent_utils::utils::create_forge_client;
use rpc::forge::InstancePhoneHomeLastContactRequest;

use crate::state::FmdsState;

pub async fn phone_home(state: &Arc<FmdsState>) -> Result<(), eyre::Error> {
    match state.outbound_governor.clone().check() {
        Ok(_) => {}
        Err(e) => return Err(eyre!("rate limit exceeded for phone_home; {}\n", e)),
    };

    let forge_client_config = state
        .forge_client_config
        .as_ref()
        .ok_or_else(|| eyre!("phone_home not configured: no forge client config"))?;

    let mut client = create_forge_client(&state.forge_api, forge_client_config).await?;

    let machine_id = state
        .machine_id
        .load_full()
        .ok_or_else(|| eyre!("phone_home: no machine_id available yet"))?;

    // Look up the instance for this machine
    let request = tonic::Request::new(*machine_id);

    let response = client.find_instance_by_machine_id(request).await?;
    let instance = response
        .into_inner()
        .instances
        .first()
        .cloned()
        .ok_or_else(|| eyre!("No instance found for machine {}", machine_id))?;

    let instance_id = instance.id;

    let request = tonic::Request::new(InstancePhoneHomeLastContactRequest { instance_id });
    let response = client
        .update_instance_phone_home_last_contact(request)
        .await?;
    let timestamp = response
        .into_inner()
        .timestamp
        .ok_or_else(|| eyre!("timestamp is empty in response"))?;

    tracing::info!(
        "Successfully phoned home for Machine {} at {}",
        machine_id,
        timestamp,
    );

    Ok(())
}
