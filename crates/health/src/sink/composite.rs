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

pub struct CompositeDataSink {
    sinks: Vec<Arc<dyn DataSink>>,
}

impl CompositeDataSink {
    pub fn new(sinks: Vec<Arc<dyn DataSink>>) -> Self {
        Self { sinks }
    }
}

impl DataSink for CompositeDataSink {
    fn handle_event<'a>(
        &'a self,
        context: EventContext,
        event: CollectorEvent,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        Box::pin(async move {
            if self.sinks.is_empty() {
                return Ok(());
            }

            let last = self.sinks.len() - 1;
            let mut owned_context = Some(context);
            let mut owned_event = Some(event);
            for (idx, sink) in self.sinks.iter().enumerate() {
                let sink_context = if idx == last {
                    owned_context
                        .take()
                        .expect("owned context should be available for final sink")
                } else {
                    owned_context
                        .as_ref()
                        .expect("owned context should be available")
                        .clone()
                };
                let sink_event = if idx == last {
                    owned_event
                        .take()
                        .expect("owned event should be available for final sink")
                } else {
                    owned_event
                        .as_ref()
                        .expect("owned event should be available")
                        .clone()
                };

                if let Err(error) = sink.handle_event(sink_context, sink_event).await {
                    tracing::warn!(error = ?error, "sink failed to process event");
                }
            }
            Ok(())
        })
    }
}
