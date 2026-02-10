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

use super::{BoxFuture, CollectorEvent, DataSink, EventContext};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::CarbideApiConnectionConfig;
use crate::sink::HealthOverride;

pub struct HealthOverrideSink {
    client: Arc<ApiClientWrapper>,
}

impl HealthOverrideSink {
    pub fn new(config: &CarbideApiConnectionConfig) -> Self {
        let client = ApiClientWrapper::new(
            config.root_ca.clone(),
            config.client_cert.clone(),
            config.client_key.clone(),
            &config.api_url,
            false,
        );
        Self {
            client: Arc::new(client),
        }
    }
}

impl DataSink for HealthOverrideSink {
    fn handle_event<'a>(
        &'a self,
        _context: EventContext,
        event: CollectorEvent,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        Box::pin(async move {
            if let CollectorEvent::HealthOverride(HealthOverride { machine_id, report }) = event {
                if let Some(ref machine_id) = machine_id {
                    self.client.submit_health_report(machine_id, report).await?;
                } else {
                    tracing::warn!(report = ?report, "Received HealthOverride event without machine_id");
                }
            }
            Ok(())
        })
    }
}
