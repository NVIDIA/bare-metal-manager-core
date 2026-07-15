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

use carbide_instrument::{DynamicLog, Event, LabelValue, LogAt, emit};
use eyre::eyre;
use forge_dpu_agent_utils::utils::create_forge_client;
use rpc::forge::InstancePhoneHomeLastContactRequest;

use crate::state::FmdsState;

/// The terminal outcome of a phone-home operation. `RateLimited` (the outbound
/// governor rejected the attempt) and `InstanceNotFound` (no instance for this
/// machine yet) are the two failures the per-RPC RED instrumentation cannot
/// see: the first never reaches an RPC, the second is a successful lookup that
/// returned nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum PhoneHomeOutcome {
    Ok,
    RateLimited,
    InstanceNotFound,
    Error,
}

/// One phone-home operation ran to completion. The event owns the failure log
/// line -- every attempt is counted, only the failures write the WARN line
/// (the success path keeps its own "Successfully phoned home" INFO log).
#[derive(Event)]
#[event(
    name = "carbide_fmds_phone_home_total",
    component = "fmds",
    log = dynamic,
    metric = counter,
    message = "Phone home failed",
    describe = "Number of FMDS tenant phone-home operations, by outcome"
)]
struct PhoneHomeCompleted {
    #[label]
    outcome: PhoneHomeOutcome,
    /// The failure's error chain; empty on success.
    #[context]
    error: String,
}

impl DynamicLog for PhoneHomeCompleted {
    fn log_at(&self) -> LogAt {
        match self.outcome {
            PhoneHomeOutcome::Ok => LogAt::Off,
            PhoneHomeOutcome::RateLimited
            | PhoneHomeOutcome::InstanceNotFound
            | PhoneHomeOutcome::Error => LogAt::Level(tracing::Level::WARN),
        }
    }
}

/// A phone-home failure tagged with the bounded outcome for the metric label,
/// carrying the eyre report for the log line and the caller. Any failure that
/// is not specifically rate-limited or instance-not-found maps to `Error`.
struct PhoneHomeError {
    outcome: PhoneHomeOutcome,
    source: eyre::Error,
}

impl From<eyre::Error> for PhoneHomeError {
    fn from(source: eyre::Error) -> Self {
        Self {
            outcome: PhoneHomeOutcome::Error,
            source,
        }
    }
}

impl From<tonic::Status> for PhoneHomeError {
    fn from(status: tonic::Status) -> Self {
        Self {
            outcome: PhoneHomeOutcome::Error,
            source: status.into(),
        }
    }
}

pub async fn phone_home(state: &Arc<FmdsState>) -> Result<(), eyre::Error> {
    let result = attempt_phone_home(state).await;
    let (outcome, error) = match &result {
        Ok(()) => (PhoneHomeOutcome::Ok, String::new()),
        Err(err) => (err.outcome, format!("{:#}", err.source)),
    };
    emit(PhoneHomeCompleted { outcome, error });
    result.map_err(|err| err.source)
}

async fn attempt_phone_home(state: &Arc<FmdsState>) -> Result<(), PhoneHomeError> {
    state
        .outbound_governor
        .clone()
        .check()
        .map_err(|e| PhoneHomeError {
            outcome: PhoneHomeOutcome::RateLimited,
            source: eyre!("rate limit exceeded for phone_home; {}\n", e),
        })?;

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
        .ok_or_else(|| PhoneHomeError {
            outcome: PhoneHomeOutcome::InstanceNotFound,
            source: eyre!("no instance found for machine {}", machine_id),
        })?;

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
        %machine_id,
        %timestamp,
        "Successfully phoned home",
    );

    Ok(())
}
