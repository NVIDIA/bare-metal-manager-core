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

//! Shared test infrastructure for DPF tests.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use kube::core::ObjectMeta;
use tokio::sync::{Notify, broadcast};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::crds::dpus_generated::*;
use crate::error::DpfError;
use crate::repository::DpuRepository;

pub(crate) struct Collector<T> {
    pub items: Mutex<Vec<T>>,
    notify: Notify,
}

impl<T> Default for Collector<T> {
    fn default() -> Self {
        Self {
            items: Mutex::new(Vec::new()),
            notify: Notify::new(),
        }
    }
}

impl<T: Clone> Collector<T> {
    pub fn push(&self, item: T) {
        self.items.lock().unwrap().push(item);
        self.notify.notify_waiters();
    }

    pub fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }

    pub fn get(&self, i: usize) -> Option<T> {
        self.items.lock().unwrap().get(i).cloned()
    }

    pub fn all(&self) -> Vec<T> {
        self.items.lock().unwrap().clone()
    }

    pub async fn wait_for(&self, n: usize) {
        let res = timeout(Duration::from_secs(5), async {
            loop {
                if self.len() >= n {
                    return;
                }
                self.notify.notified().await;
            }
        })
        .await;
        if res.is_err() {
            panic!("Timed out waiting for {} items, got {}", n, self.len());
        }
    }
}

/// Minimal DpuRepository mock that emits DPUs via broadcast channel.
#[derive(Clone)]
pub(crate) struct WatcherMock {
    pub dpu_tx: broadcast::Sender<DPU>,
    cancel: CancellationToken,
    watch_count: Arc<AtomicUsize>,
    watch_notify: Arc<Notify>,
}

impl WatcherMock {
    pub fn new() -> Self {
        let (dpu_tx, _) = broadcast::channel(100);
        Self {
            dpu_tx,
            cancel: CancellationToken::new(),
            watch_count: Arc::default(),
            watch_notify: Arc::new(Notify::new()),
        }
    }

    pub fn emit_dpu(&self, dpu: DPU) {
        let _ = self.dpu_tx.send(dpu);
    }

    pub async fn wait_for_watchers(&self, n: usize) {
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

    pub async fn wait_for_receivers(&self, n: usize) {
        let res = timeout(Duration::from_secs(5), async {
            loop {
                if self.dpu_tx.receiver_count() == n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if res.is_err() {
            panic!(
                "Timed out waiting for {} receivers, got {}",
                n,
                self.dpu_tx.receiver_count()
            );
        }
    }
}

#[async_trait]
impl DpuRepository for WatcherMock {
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
                        let _ = handler(Arc::new(dpu)).await;
                    }
                }
            }
        }
    }
}

pub(crate) fn make_status(phase: DpuStatusPhase) -> DpuStatus {
    DpuStatus {
        addresses: None,
        bf_cfg_file: None,
        bfb_file: None,
        bfb_version: None,
        conditions: None,
        dpf_version: None,
        dpu_install_interface: None,
        dpu_mode: None,
        firmware: None,
        observed_generation: None,
        pci_device: None,
        phase,
        post_provisioning_node_effect: None,
        required_reset: None,
    }
}

pub(crate) fn make_dpu(
    ns: &str,
    name: &str,
    device: &str,
    node: &str,
    phase: DpuStatusPhase,
) -> DPU {
    DPU {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(ns.into()),
            ..Default::default()
        },
        spec: DpuSpec {
            bfb: "bfb".into(),
            bmc_ip: Some("10.0.0.100".into()),
            cluster: None,
            dpu_device_name: device.into(),
            dpu_flavor: Some("flavor".into()),
            dpu_node_name: node.into(),
            node_effect: None,
            pci_address: None,
            serial_number: "SN".into(),
        },
        status: Some(make_status(phase)),
    }
}

pub(crate) fn make_dpu_reboot(ns: &str, name: &str, device: &str, node: &str) -> DPU {
    make_dpu(ns, name, device, node, DpuStatusPhase::Rebooting)
}

pub(crate) fn make_dpu_labeled(
    ns: &str,
    name: &str,
    device: &str,
    node: &str,
    phase: DpuStatusPhase,
    mid: &str,
) -> DPU {
    let mut dpu = make_dpu(ns, name, device, node, phase);
    dpu.metadata.labels = Some(BTreeMap::from([(
        "carbide.nvidia.com/dpu-machine-id".into(),
        mid.into(),
    )]));
    dpu
}
