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

use tokio::sync::mpsc;

use super::{CollectorEvent, DataSink, EventContext};
use crate::HealthError;

struct SinkEvent {
    context: Arc<EventContext>,
    event: Arc<CollectorEvent>,
}

pub struct CompositeDataSink {
    worker_senders: Vec<mpsc::UnboundedSender<SinkEvent>>,
    fallback_sinks: Vec<Arc<dyn DataSink>>,
}

impl CompositeDataSink {
    pub fn new(sinks: Vec<Arc<dyn DataSink>>) -> Self {
        let mut worker_senders = Vec::with_capacity(sinks.len());
        let mut fallback_sinks = Vec::new();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            for sink in sinks {
                let (sender, mut receiver) = mpsc::unbounded_channel::<SinkEvent>();
                worker_senders.push(sender);

                handle.spawn(async move {
                    while let Some(SinkEvent { context, event }) = receiver.recv().await {
                        if let Err(error) = sink.handle_event(&context, &event) {
                            tracing::warn!(error = ?error, "sink failed to process event");
                        }
                    }
                });
            }
        } else {
            fallback_sinks = sinks;
        }

        Self {
            worker_senders,
            fallback_sinks,
        }
    }
}

impl DataSink for CompositeDataSink {
    fn handle_event(
        &self,
        context: &EventContext,
        event: &CollectorEvent,
    ) -> Result<(), HealthError> {
        if !self.worker_senders.is_empty() {
            let context = Arc::new(context.clone());
            let event = Arc::new(event.clone());

            for sender in &self.worker_senders {
                if let Err(error) = sender.send(SinkEvent {
                    context: context.clone(),
                    event: event.clone(),
                }) {
                    tracing::warn!(error = ?error, "failed to enqueue sink event");
                }
            }

            return Ok(());
        }

        for sink in &self.fallback_sinks {
            if let Err(error) = sink.handle_event(context, event) {
                tracing::warn!(error = ?error, "sink failed to process event");
            }
        }

        Ok(())
    }
}
