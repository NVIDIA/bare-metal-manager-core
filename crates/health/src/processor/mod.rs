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

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

mod health_report;
mod intrusion_events;
mod leak_events;
mod rack_leak;
pub use health_report::HealthReportProcessor;
pub use intrusion_events::BmcIntrusionSyncEventNode;
pub use leak_events::LeakSyncEventNode;
pub use rack_leak::RackLeakProcessor;

use crate::metrics::{ComponentMetrics, MetricsManager};
use crate::sink::{EventContext, HealthEvent, SyncEventNode};

/// A queued event plus the set of nodes that may not re-consume it, so a node
/// never re-processes events derived from its own output.
struct PendingEvent<'a> {
    event: Cow<'a, HealthEvent>,
    blocked_processors: Vec<bool>,
}

/// Runs a pipeline of [`SyncEventNode`]s: each input event is offered to every
/// interested node, and any events a node emits are fed back through the graph
/// (excluding the emitting node) until the work queue drains.
pub struct EventGraph {
    nodes: Vec<Arc<dyn SyncEventNode>>,
    component_metrics: Arc<ComponentMetrics>,
}

impl EventGraph {
    /// Builds a graph over `nodes`. Callers must only construct this when at
    /// least one node is configured.
    pub fn new(nodes: Vec<Arc<dyn SyncEventNode>>, metrics_manager: Arc<MetricsManager>) -> Self {
        debug_assert!(
            !nodes.is_empty(),
            "EventGraph should only be used when nodes are configured"
        );
        Self {
            nodes,
            component_metrics: metrics_manager.component_metrics(),
        }
    }

    /// Offers `current_event` to every interested, non-blocked node and queues
    /// the events they emit for further processing.
    fn next_events(
        &self,
        context: &EventContext,
        current_event: &HealthEvent,
        blocked_nodes: &[bool],
        queue: &mut VecDeque<PendingEvent>,
    ) {
        for (node_idx, node) in self.nodes.iter().enumerate() {
            if blocked_nodes[node_idx] {
                continue;
            }

            if !node.interested_in(current_event) {
                continue;
            }

            let start = Instant::now();
            let emitted = node.handle_event(context, current_event);
            self.component_metrics.record_operation(
                crate::metrics::ComponentKind::Processor,
                node.node_type(),
                start.elapsed(),
                true,
            );
            if emitted.is_empty() {
                continue;
            }

            for event in emitted {
                let mut next_blocked_processors = blocked_nodes.to_vec();
                next_blocked_processors[node_idx] = true;
                queue.push_back(PendingEvent {
                    event: Cow::Owned(event),
                    blocked_processors: next_blocked_processors,
                });
            }
        }
    }
}

impl SyncEventNode for EventGraph {
    fn node_type(&self) -> &'static str {
        "event_graph"
    }

    fn handle_event(&self, context: &EventContext, event: &HealthEvent) -> Vec<HealthEvent> {
        let mut queue = VecDeque::from(vec![PendingEvent {
            event: Cow::Borrowed(event),
            blocked_processors: vec![false; self.nodes.len()],
        }]);

        while let Some(current) = queue.pop_front() {
            self.next_events(
                context,
                &current.event,
                &current.blocked_processors,
                &mut queue,
            );
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::BmcAddr;
    use crate::metrics::MetricsManager;

    struct CountingSink {
        counter: Arc<AtomicUsize>,
    }

    impl SyncEventNode for CountingSink {
        fn node_type(&self) -> &'static str {
            "counting_sink"
        }

        fn handle_event(&self, _context: &EventContext, _event: &HealthEvent) -> Vec<HealthEvent> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }
    }

    struct SelfReemittingProcessor {
        counter: Arc<AtomicUsize>,
    }

    impl SyncEventNode for SelfReemittingProcessor {
        fn node_type(&self) -> &'static str {
            "self_reemitting_processor"
        }

        fn handle_event(&self, _context: &EventContext, event: &HealthEvent) -> Vec<HealthEvent> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            vec![event.clone()]
        }
    }

    fn context() -> EventContext {
        EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        }
    }

    #[test]
    fn processor_does_not_reconsume_its_own_descendants() {
        let processor_counter = Arc::new(AtomicUsize::new(0));
        let sink_counter = Arc::new(AtomicUsize::new(0));
        let metrics_manager =
            Arc::new(MetricsManager::new("test").expect("should create metrics manager"));
        let pipeline = EventGraph::new(
            vec![
                Arc::new(CountingSink {
                    counter: sink_counter.clone(),
                }),
                Arc::new(SelfReemittingProcessor {
                    counter: processor_counter.clone(),
                }),
            ],
            metrics_manager,
        );

        let event = HealthEvent::MeasurementObserved(
            crate::sink::MetricSample {
                key: "k".to_string(),
                name: "n".to_string(),
                metric_type: "gauge".to_string(),
                unit: "count".to_string(),
                value: 1.0,
                labels: Vec::new(),
                context: None,
            }
            .into(),
        );
        pipeline.handle_event(&context(), &event);

        assert_eq!(processor_counter.load(Ordering::SeqCst), 1);
        assert_eq!(sink_counter.load(Ordering::SeqCst), 2);
    }
}
