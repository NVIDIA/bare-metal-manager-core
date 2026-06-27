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
use std::time::Instant;

use super::{EventContext, HealthEvent, SyncEventNode};
use crate::metrics::{ComponentKind, ComponentMetrics, MetricsManager};

/// A [`SyncEventNode`] that fans every event out to a set of inner sinks,
/// recording per-sink timing metrics. Terminal node: it never emits derived
/// events.
pub struct CompositeSyncEventNode {
    sinks: Vec<Arc<dyn SyncEventNode>>,
    component_metrics: Arc<ComponentMetrics>,
}

impl CompositeSyncEventNode {
    /// Creates a composite over `sinks`, sourcing timing metrics from
    /// `metrics_manager`.
    pub fn new(sinks: Vec<Arc<dyn SyncEventNode>>, metrics_manager: Arc<MetricsManager>) -> Self {
        Self {
            sinks,
            component_metrics: metrics_manager.component_metrics(),
        }
    }

    /// Records the time a single inner sink spent handling one event.
    fn record_sink_operation(&self, sink: &dyn SyncEventNode, duration: std::time::Duration) {
        self.component_metrics.record_operation(
            ComponentKind::Sink,
            sink.node_type(),
            duration,
            true,
        );
    }
}

impl SyncEventNode for CompositeSyncEventNode {
    fn node_type(&self) -> &'static str {
        "composite_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &HealthEvent) -> Vec<HealthEvent> {
        for sink in &self.sinks {
            if !sink.interested_in(event) {
                continue;
            }
            let start = Instant::now();
            sink.handle_event(context, event);
            self.record_sink_operation(sink.as_ref(), start.elapsed());
        }
        Vec::new()
    }
}
