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
use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Display, Formatter, Write};
use std::sync::RwLock;

use chrono::Local;
use tokio::sync::{mpsc, oneshot};
use tracing::field::Field;
use tracing::span::Attributes;
use tracing::{Event, Id, Subscriber, field};
use tracing_subscriber::layer::Context;
use uuid::Uuid;

/// [`TuiHostLogs`] holds logs for each Machine-a-tron HostMachine, so that we can display them in the TUI.
///
/// Logs are subscribed via [`TuiHostLogs::make_tracing_layer`], which is injected as a [`tracing_subscriber::Layer`], and
/// watches for spans and events that have a `mat_host_id` field set.
#[derive(Clone, Debug)]
pub struct TuiHostLogs {
    message_tx: mpsc::UnboundedSender<HostLogCommand>,
}

impl TuiHostLogs {
    pub async fn get_logs(&self, host_id: Uuid) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        _ = self
            .message_tx
            .send(HostLogCommand::GetLogs { host_id, reply: tx });
        rx.await.unwrap_or_default()
    }

    /// Start a new [`tokio::task`] which ingests logs and allows extracting them via get_logs. This
    /// should only be done once.
    pub fn start_new(max_size: usize) -> TuiHostLogs {
        let mut storage = HostLogStorage {
            logs_by_host: HashMap::new(),
        };
        let (message_tx, mut message_rx) = mpsc::unbounded_channel::<HostLogCommand>();
        tokio::spawn(async move {
            loop {
                let Some(command) = message_rx.recv().await else {
                    break;
                };

                match command {
                    HostLogCommand::Log { host_id, message } => {
                        // VecDeque is a ring-buffer, it should be O(1) to remove the first element,
                        // and O(1) to add a new element.
                        let deque = storage
                            .logs_by_host
                            .entry(host_id)
                            .or_insert_with(|| VecDeque::with_capacity(max_size));

                        if deque.len() >= max_size {
                            _ = deque.pop_front();
                        }
                        deque.push_back(message);
                    }
                    HostLogCommand::GetLogs { host_id, reply } => {
                        _ = reply.send(
                            storage
                                .logs_by_host
                                .get(&host_id)
                                .map(|q| q.iter().cloned().collect::<Vec<_>>())
                                .unwrap_or_default(),
                        )
                    }
                }
            }
        });

        TuiHostLogs { message_tx }
    }

    pub fn make_tracing_layer<S: tracing::Subscriber>(&self) -> impl tracing_subscriber::Layer<S> {
        HostLogSubscriber {
            host_log: self.clone(),
            span_infos: RwLock::new(HashMap::new()),
        }
    }

    fn log(&self, host_id: Uuid, message: String) {
        _ = self
            .message_tx
            .send(HostLogCommand::Log { host_id, message })
    }
}

struct HostLogStorage {
    logs_by_host: HashMap<Uuid, VecDeque<String>>,
}

enum HostLogCommand {
    Log {
        host_id: Uuid,
        message: String,
    },
    GetLogs {
        host_id: Uuid,
        reply: oneshot::Sender<Vec<String>>,
    },
}

struct HostLogSubscriber {
    host_log: TuiHostLogs,
    span_infos: RwLock<HashMap<Id, HostEventInfo>>,
}

/// Returns true if the event metadata is something we care about
fn should_record(metadata: &tracing::Metadata) -> bool {
    metadata.target().starts_with("machine_a_tron::") || metadata.target().starts_with("bmc_mock::")
}

impl<S: Subscriber> tracing_subscriber::Layer<S> for HostLogSubscriber {
    /// Watch for new spans being created, and record if they have a `mat_host_id` field set. If so,
    /// record the fields from this span in self.span_metadata, so that we can associate those fields
    /// with events inside that span.
    ///
    /// Example:
    ///
    /// ```
    /// use uuid::Uuid;
    /// let mat_host_id = Uuid::new_v4();
    /// // Create a span with mat_host_id set, plus other metadata. This should trigger [`on_new_span`],
    /// // and we record the `mat_host_id` and `foo` fields.
    /// tracing::info_span!("foo", mat_host_id = %mat_host_id, foo = "bar").in_scope(|| {
    ///     // ... later...
    ///     tracing::info!(foo2 = "bar2", "hello") // on_event will look at the current span and find
    ///                                            // the "mat_host_id" and "foo" fields already set
    /// })
    /// ```
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if !should_record(attrs.metadata()) {
            return;
        }

        let mut host_event_info = HostEventInfo::default();
        if let Some(span_id) = ctx.current_span().id() {
            // Allow inheriting the span_info from the current span
            if let Some(parent_span_info) = self.span_infos.read().unwrap().get(span_id).cloned() {
                host_event_info = parent_span_info;
            }
        }

        // Record info from the new span
        attrs.record(&mut host_event_info);

        // If we found a `mat_host_id`, record the info to this span's Id
        if host_event_info.host_id.is_some() {
            self.span_infos
                .write()
                .unwrap()
                .insert(id.clone(), host_event_info);
        }
    }

    fn on_close(&self, id: Id, _ctx: Context<'_, S>) {
        self.span_infos.write().unwrap().remove(&id);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !should_record(event.metadata()) {
            return;
        }

        let mut event_info = HostEventInfo::default();

        // If this event is inside a span which already has a mat_host_id recorded, inherit its metadata
        if let Some(id) = ctx.current_span().id()
            && let Some(span_metadata) = self.span_infos.read().unwrap().get(id)
        {
            event_info = span_metadata.clone();
        }

        // Record the info from this event
        event.record(&mut event_info);

        if let Some(host_id) = event_info.host_id.as_ref()
            && let Ok(host_uuid) = Uuid::parse_str(host_id)
        {
            self.host_log.log(
                host_uuid,
                format!(
                    "{}: {} {}",
                    Local::now(),
                    event.metadata().target(),
                    event_info
                ),
            );
        }
    }
}

#[derive(Default, Clone)]
struct HostEventInfo {
    host_id: Option<String>,
    dpu_index: Option<String>,
    message: Option<String>,
    fields: Vec<String>,
}

impl field::Visit for HostEventInfo {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        match field.name() {
            "mat_host_id" => self.host_id = Some(format!("{value:?}")),
            "message" => self.message = Some(format!("{value:?}")),
            "dpu_index" => self.dpu_index = Some(format!("{value:?}")),
            _ => self.fields.push(format!("{}={:?}", field.name(), value)),
        }
    }
}

impl Display for HostEventInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(dpu_index) = self.dpu_index.as_ref() {
            write!(f, "DPU {dpu_index}: ")?;
        }
        if let Some(message) = self.message.as_ref() {
            f.write_str(message)?;
        }
        for field in &self.fields {
            f.write_char(' ')?;
            f.write_str(field)?;
        }

        Ok(())
    }
}
