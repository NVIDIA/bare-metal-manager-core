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

//! Watcher for DPU resource events.
//!
//! Uses the repository `watch()` trait method to receive DPU events.
//! The repository implementation handles retries and requeuing when
//! handlers return `Err`.
//!
//! Callbacks may fire on any update to a DPU resource, not only on
//! phase transitions. All handlers must be idempotent.
//!
//! ## Example
//!
//! ```ignore
//! let watcher = DpuWatcherBuilder::new(repo, "dpf-operator-system")
//!     .on_dpu_event(|event| async move {
//!         println!("Phase: {:?}", event.phase);
//!         Ok(())
//!     })
//!     .on_reboot_required(|event| async move {
//!         enqueue_host_reboot(&event.host_bmc_ip).await?;
//!         Ok(())
//!     })
//!     .start();
//! ```

use std::future::Future;
use std::sync::Arc;

use crate::crds::dpus_generated::{DPU, DpuStatusPhase};
use crate::error::DpfError;
use crate::repository::DpuRepository;
use crate::types::{
    DpuErrorEvent, DpuEvent, DpuPhase, DpuReadyEvent, MaintenanceEvent, RebootRequiredEvent,
};

/// Callback for DPU state changes. Implemented automatically for all `Fn(T) -> Future`.
/// Purpose is to allow for generic async callbacks without having to box and pin the closure.
pub trait DPUStateCallback<T>: Fn(T) -> Self::Fut + Send + Sync + 'static {
    type Fut: Future<Output = Result<(), DpfError>> + Send + 'static;
}

impl<T, F, Fut> DPUStateCallback<T> for F
where
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
{
    type Fut = Fut;
}

// for defaulting to no-op callbacks in the builder
type NoopFn<T> = fn(T) -> std::future::Ready<Result<(), DpfError>>;

struct Callbacks<DE, RB, RD, MN, ER> {
    dpu_event: DE,
    reboot: RB,
    ready: RD,
    maintenance: MN,
    error: ER,
}

/// The watcher only cares about how the events are translated into the callbacks,
/// not the actual event gathering. The repository implementation handles procuring
/// the events, as well as retries and requeuing when handlers return `Err`.
pub struct DpuWatcher {
    watcher_task: tokio::task::JoinHandle<()>,
}

/// The watcher continues running until this struct is dropped.
impl Drop for DpuWatcher {
    fn drop(&mut self) {
        self.watcher_task.abort();
    }
}

/// Builder for creating a DPU watcher.
pub struct DpuWatcherBuilder<
    R: DpuRepository,
    DE = NoopFn<DpuEvent>,
    RB = NoopFn<RebootRequiredEvent>,
    RD = NoopFn<DpuReadyEvent>,
    MN = NoopFn<MaintenanceEvent>,
    ER = NoopFn<DpuErrorEvent>,
> {
    repo: Arc<R>,
    namespace: String,
    cbs: Callbacks<DE, RB, RD, MN, ER>,
}

impl<R: DpuRepository> DpuWatcherBuilder<R> {
    pub fn new(repo: Arc<R>, namespace: impl Into<String>) -> Self {
        Self {
            repo,
            namespace: namespace.into(),
            cbs: Callbacks {
                dpu_event: |_| std::future::ready(Ok(())),
                reboot: |_| std::future::ready(Ok(())),
                ready: |_| std::future::ready(Ok(())),
                maintenance: |_| std::future::ready(Ok(())),
                error: |_| std::future::ready(Ok(())),
            },
        }
    }
}

/// This is a type state builder pattern. It's extra boilerplate, but we get generic
/// function types for the callbacks instead of boxing and pinning the closures.
impl<R: DpuRepository, DE, RB, RD, MN, ER> DpuWatcherBuilder<R, DE, RB, RD, MN, ER> {
    /// Register a callback for DPU events.
    ///
    /// The callback is invoked on every observed update to a DPU, not only
    /// on phase transitions. The handler must be idempotent.
    pub fn on_dpu_event<F, Fut>(self, callback: F) -> DpuWatcherBuilder<R, F, RB, RD, MN, ER>
    where
        F: Fn(DpuEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        DpuWatcherBuilder {
            repo: self.repo,
            namespace: self.namespace,
            cbs: Callbacks {
                dpu_event: callback,
                reboot: self.cbs.reboot,
                ready: self.cbs.ready,
                maintenance: self.cbs.maintenance,
                error: self.cbs.error,
            },
        }
    }

    /// Register a callback for when a host reboot is required.
    ///
    /// Invoked on every update where the DPU is in the Rebooting phase, not
    /// only on transitions into that phase. The handler must be idempotent.
    ///
    /// Return `Ok(())` to acknowledge the event. Return `Err` to have the
    /// repository implementation retry after a backoff period.
    pub fn on_reboot_required<F, Fut>(self, callback: F) -> DpuWatcherBuilder<R, DE, F, RD, MN, ER>
    where
        F: Fn(RebootRequiredEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        DpuWatcherBuilder {
            repo: self.repo,
            namespace: self.namespace,
            cbs: Callbacks {
                dpu_event: self.cbs.dpu_event,
                reboot: callback,
                ready: self.cbs.ready,
                maintenance: self.cbs.maintenance,
                error: self.cbs.error,
            },
        }
    }

    /// Register a callback for when a DPU is in the Ready phase.
    ///
    /// Invoked on every update where the DPU is in the Ready phase, not
    /// only on transitions into that phase. The handler must be idempotent.
    pub fn on_dpu_ready<F, Fut>(self, callback: F) -> DpuWatcherBuilder<R, DE, RB, F, MN, ER>
    where
        F: Fn(DpuReadyEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        DpuWatcherBuilder {
            repo: self.repo,
            namespace: self.namespace,
            cbs: Callbacks {
                dpu_event: self.cbs.dpu_event,
                reboot: self.cbs.reboot,
                ready: callback,
                maintenance: self.cbs.maintenance,
                error: self.cbs.error,
            },
        }
    }

    /// Register a callback for when the DPU is in the NodeEffect phase.
    ///
    /// Invoked on every update where the DPU is in the NodeEffect phase, not
    /// only on transitions into that phase. The handler must be idempotent.
    ///
    /// Return `Ok(())` to acknowledge the event. Return `Err` to have the
    /// repository implementation retry after a backoff period.
    pub fn on_maintenance_needed<F, Fut>(
        self,
        callback: F,
    ) -> DpuWatcherBuilder<R, DE, RB, RD, F, ER>
    where
        F: Fn(MaintenanceEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        DpuWatcherBuilder {
            repo: self.repo,
            namespace: self.namespace,
            cbs: Callbacks {
                dpu_event: self.cbs.dpu_event,
                reboot: self.cbs.reboot,
                ready: self.cbs.ready,
                maintenance: callback,
                error: self.cbs.error,
            },
        }
    }

    /// Register a callback for when a DPU is in the Error phase.
    ///
    /// Invoked on every update where the DPU is in the Error phase, not
    /// only on transitions into that phase. The handler must be idempotent.
    ///
    /// Return `Ok(())` to acknowledge the event. Return `Err` to have the
    /// repository implementation retry after a backoff period.
    pub fn on_error<F, Fut>(self, callback: F) -> DpuWatcherBuilder<R, DE, RB, RD, MN, F>
    where
        F: Fn(DpuErrorEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        DpuWatcherBuilder {
            repo: self.repo,
            namespace: self.namespace,
            cbs: Callbacks {
                dpu_event: self.cbs.dpu_event,
                reboot: self.cbs.reboot,
                ready: self.cbs.ready,
                maintenance: self.cbs.maintenance,
                error: callback,
            },
        }
    }
}

impl<R, DE, RB, RD, MN, ER> DpuWatcherBuilder<R, DE, RB, RD, MN, ER>
where
    R: DpuRepository,
    DE: DPUStateCallback<DpuEvent>,
    RB: DPUStateCallback<RebootRequiredEvent>,
    RD: DPUStateCallback<DpuReadyEvent>,
    MN: DPUStateCallback<MaintenanceEvent>,
    ER: DPUStateCallback<DpuErrorEvent>,
{
    /// Start watching for events.
    ///
    /// Returns a handle that stops the watcher when dropped.
    pub fn start(self) -> DpuWatcher {
        let cbs = Arc::new(self.cbs);

        let handler = move |dpu: Arc<DPU>| {
            let cbs = cbs.clone();
            async move {
                let Some(status) = &dpu.status else {
                    return Ok(());
                };
                let Some(dpu_name) = &dpu.metadata.name else {
                    return Ok(());
                };

                let device_name = dpu.spec.dpu_device_name.clone();
                let phase = DpuPhase::from(status.phase.clone());
                let node_name = dpu.spec.dpu_node_name.clone();

                (cbs.dpu_event)(DpuEvent {
                    dpu_name: dpu_name.clone(),
                    device_name: device_name.clone(),
                    node_name: node_name.clone(),
                    phase,
                })
                .await?;

                if matches!(status.phase, DpuStatusPhase::NodeEffect) {
                    (cbs.maintenance)(MaintenanceEvent {
                        dpu_name: dpu_name.clone(),
                        node_name: node_name.clone(),
                    })
                    .await?;
                }

                if matches!(status.phase, DpuStatusPhase::Ready) {
                    (cbs.ready)(DpuReadyEvent {
                        dpu_name: dpu_name.clone(),
                        device_name: device_name.clone(),
                        node_name: node_name.clone(),
                    })
                    .await?;
                }

                if matches!(status.phase, DpuStatusPhase::Error) {
                    (cbs.error)(DpuErrorEvent {
                        dpu_name: dpu_name.clone(),
                        device_name: device_name.clone(),
                        node_name: node_name.clone(),
                    })
                    .await?;
                }

                if matches!(status.phase, DpuStatusPhase::Rebooting) {
                    (cbs.reboot)(RebootRequiredEvent {
                        dpu_name: dpu_name.clone(),
                        node_name: node_name.clone(),
                        host_bmc_ip: dpu.spec.bmc_ip.clone().unwrap_or_default(),
                    })
                    .await?;
                }

                Ok(())
            }
        };

        DpuWatcher {
            watcher_task: tokio::spawn(self.repo.watch(&self.namespace, handler)),
        }
    }
}
