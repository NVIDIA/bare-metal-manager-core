/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Watcher callback error propagation tests.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use tokio::sync::{Notify, broadcast};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::helpers::{Collector, make_dpu};
use crate::crds::dpus_generated::*;
use crate::error::DpfError;
use crate::repository::DpuRepository;
use crate::types::*;
use crate::watcher::DpuWatcherBuilder;

const TEST_NS: &str = "watcher-error-test-ns";

/// Mock that captures handler errors.
#[derive(Clone)]
struct ErrorCapturingMock {
    dpu_tx: broadcast::Sender<DPU>,
    cancel: CancellationToken,
    watch_count: Arc<AtomicUsize>,
    watch_notify: Arc<Notify>,
    errors: Arc<Collector<String>>,
}

impl ErrorCapturingMock {
    fn new() -> Self {
        let (dpu_tx, _) = broadcast::channel(100);
        Self {
            dpu_tx,
            cancel: CancellationToken::new(),
            watch_count: Arc::default(),
            watch_notify: Arc::new(Notify::new()),
            errors: Arc::new(Collector::default()),
        }
    }

    fn emit_dpu(&self, dpu: DPU) {
        let _ = self.dpu_tx.send(dpu);
    }

    async fn wait_for_watchers(&self, n: usize) {
        let res = timeout(Duration::from_secs(5), async {
            loop {
                if self.watch_count.load(Ordering::SeqCst) >= n {
                    return;
                }
                self.watch_notify.notified().await;
            }
        })
        .await;
        if res.is_err() {
            panic!(
                "Timed out waiting for {} watchers, got {}",
                n,
                self.watch_count.load(Ordering::SeqCst)
            );
        }
    }
}

#[async_trait]
impl DpuRepository for ErrorCapturingMock {
    async fn get(&self, _: &str, _: &str) -> Result<Option<DPU>, DpfError> {
        Ok(None)
    }
    async fn list(&self, _: &str) -> Result<Vec<DPU>, DpfError> {
        Ok(vec![])
    }
    async fn patch_status(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
        Ok(())
    }
    async fn delete(&self, _: &str, _: &str) -> Result<(), DpfError> {
        Ok(())
    }
    fn watch<F, Fut>(&self, _: &str, handler: F) -> impl Future<Output = ()> + Send + 'static
    where
        F: Fn(Arc<DPU>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        let rx = self.dpu_tx.subscribe();
        let cancel = self.cancel.clone();
        let errors = self.errors.clone();
        self.watch_count.fetch_add(1, Ordering::SeqCst);
        self.watch_notify.notify_waiters();
        async move {
            let stream =
                tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|r| async { r.ok() });
            tokio::pin!(stream);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    item = stream.next() => {
                        let Some(dpu) = item else { break };
                        if let Err(e) = handler(Arc::new(dpu)).await {
                            errors.push(e.to_string());
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn test_callback_error_propagated() {
    let m = Arc::new(ErrorCapturingMock::new());

    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(|_event| async move {
            Err(DpfError::InvalidState("dpu event handler failed".into()))
        })
        .start();

    m.wait_for_watchers(1).await;
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev", "n1", DpuStatusPhase::Ready));

    m.errors.wait_for(1).await;
    let errors = m.errors.all();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("dpu event handler failed"),
        "Expected error message, got: {}",
        errors[0]
    );
}

#[tokio::test]
async fn test_callback_error_short_circuits() {
    let m = Arc::new(ErrorCapturingMock::new());
    let ready_events = Arc::new(Collector::<DpuReadyEvent>::default());
    let dpu_events = Arc::new(Collector::<DpuEvent>::default());

    let dc = dpu_events.clone();

    let _h = DpuWatcherBuilder::new(m.clone(), TEST_NS)
        .on_dpu_event(move |e| {
            let dc = dc.clone();
            async move {
                dc.push(e);
                Err(DpfError::InvalidState("dpu event handler failed".into()))
            }
        })
        .on_dpu_ready({
            let rc = ready_events.clone();
            move |e| {
                let rc = rc.clone();
                async move {
                    rc.push(e);
                    Ok(())
                }
            }
        })
        .start();

    m.wait_for_watchers(1).await;

    // on_dpu_event fires first, returns Err,
    // so on_dpu_ready should NOT fire due to early return via `?`
    m.emit_dpu(make_dpu(TEST_NS, "d1", "dev", "n1", DpuStatusPhase::Ready));

    m.errors.wait_for(1).await;
    assert_eq!(dpu_events.len(), 1);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        ready_events.len(),
        0,
        "on_dpu_ready should not fire when on_dpu_event returns Err"
    );
}
