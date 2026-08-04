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

//! Transport- and application-independent bounded admission.
//!
//! The contract deliberately grants an RAII execution permit instead of
//! accepting a handler future. A scheduler-backed implementation can therefore
//! dispatch a grant/completion bridge while the original request task continues
//! to own and execute its handler future.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum RejectionReason {
    QueueFull,
    QueueTimeout,
    ControllerUnavailable,
    ShuttingDown,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmissionLimitsError {
    #[error("max_work_in_flight must be greater than zero")]
    ZeroWorkCapacity,
    #[error("max_work_in_flight must not exceed {maximum}")]
    WorkCapacityTooLarge { maximum: usize },
    #[error("max_pending must be greater than zero")]
    ZeroPendingCapacity,
    #[error("max_pending must not exceed {maximum}")]
    PendingCapacityTooLarge { maximum: usize },
    #[error("pending_timeout must be greater than zero")]
    ZeroPendingTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionLimits {
    max_work_in_flight: usize,
    max_pending: usize,
    pending_timeout: Duration,
}

impl AdmissionLimits {
    pub(crate) fn new(
        max_work_in_flight: usize,
        max_pending: usize,
        pending_timeout: Duration,
    ) -> Result<Self, AdmissionLimitsError> {
        if max_work_in_flight == 0 {
            return Err(AdmissionLimitsError::ZeroWorkCapacity);
        }
        if max_work_in_flight > Semaphore::MAX_PERMITS {
            return Err(AdmissionLimitsError::WorkCapacityTooLarge {
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        if max_pending == 0 {
            return Err(AdmissionLimitsError::ZeroPendingCapacity);
        }
        if max_pending > Semaphore::MAX_PERMITS {
            return Err(AdmissionLimitsError::PendingCapacityTooLarge {
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        if pending_timeout.is_zero() {
            return Err(AdmissionLimitsError::ZeroPendingTimeout);
        }

        Ok(Self {
            max_work_in_flight,
            max_pending,
            pending_timeout,
        })
    }

    pub(crate) const fn max_work_in_flight(self) -> usize {
        self.max_work_in_flight
    }

    pub(crate) const fn max_pending(self) -> usize {
        self.max_pending
    }
}

pub(super) trait AdmissionObserver: Send + Sync + 'static {
    fn admitted(&self) {}

    fn pending_finished(&self, _duration: Duration) {}

    fn execution_finished(&self, _duration: Duration) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AdmissionSnapshot {
    pub(super) work_in_flight: usize,
    pub(super) pending: usize,
}

pub(super) struct SemaphoreAdmission {
    limits: AdmissionLimits,
    work_slots: Arc<Semaphore>,
    pending_slots: Arc<Semaphore>,
    shutdown: CancellationToken,
    observer: Arc<dyn AdmissionObserver>,
}

impl SemaphoreAdmission {
    pub(super) fn new(
        limits: AdmissionLimits,
        shutdown: CancellationToken,
        observer: Arc<dyn AdmissionObserver>,
    ) -> Arc<Self> {
        Arc::new(Self {
            limits,
            work_slots: Arc::new(Semaphore::new(limits.max_work_in_flight())),
            pending_slots: Arc::new(Semaphore::new(limits.max_pending())),
            shutdown,
            observer,
        })
    }

    /// Wait for admission associated with opaque scheduling metadata.
    ///
    /// The semaphore backend does not inspect `metadata`. A future fair
    /// scheduler can use it to classify work without changing the permit-based
    /// middleware contract.
    pub(super) async fn acquire<M>(&self, _metadata: M) -> Result<ExecutionPermit, RejectionReason>
    where
        M: Send,
    {
        if self.shutdown.is_cancelled() {
            return Err(RejectionReason::ShuttingDown);
        }

        match Arc::clone(&self.work_slots).try_acquire_owned() {
            Ok(permit) => return Ok(self.admit(permit)),
            Err(TryAcquireError::Closed) => {
                return Err(RejectionReason::ControllerUnavailable);
            }
            Err(TryAcquireError::NoPermits) => {}
        }

        let pending_permit = match Arc::clone(&self.pending_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(RejectionReason::QueueFull),
            Err(TryAcquireError::Closed) => {
                return Err(RejectionReason::ControllerUnavailable);
            }
        };

        let pending_wait = PendingWait {
            _permit: pending_permit,
            started: Instant::now(),
            observer: Arc::clone(&self.observer),
        };
        let acquisition = tokio::time::timeout(
            self.limits.pending_timeout,
            Arc::clone(&self.work_slots).acquire_owned(),
        );
        let result = tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(RejectionReason::ShuttingDown),
            result = acquisition => match result {
                Ok(Ok(permit)) => Ok(permit),
                Ok(Err(_)) => Err(RejectionReason::ControllerUnavailable),
                Err(_) => Err(RejectionReason::QueueTimeout),
            },
        };
        drop(pending_wait);

        result.map(|permit| self.admit(permit))
    }

    fn admit(&self, permit: OwnedSemaphorePermit) -> ExecutionPermit {
        self.observer.admitted();
        ExecutionPermit {
            _permit: permit,
            started: Instant::now(),
            observer: Arc::clone(&self.observer),
        }
    }

    pub(super) fn snapshot(&self) -> AdmissionSnapshot {
        AdmissionSnapshot {
            work_in_flight: self
                .limits
                .max_work_in_flight
                .saturating_sub(self.work_slots.available_permits()),
            pending: self
                .limits
                .max_pending
                .saturating_sub(self.pending_slots.available_permits()),
        }
    }

    #[cfg(test)]
    fn close(&self) {
        self.work_slots.close();
    }
}

pub(super) struct ExecutionPermit {
    _permit: OwnedSemaphorePermit,
    started: Instant,
    observer: Arc<dyn AdmissionObserver>,
}

impl std::fmt::Debug for ExecutionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExecutionPermit")
    }
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.observer.execution_finished(self.started.elapsed());
    }
}

struct PendingWait {
    _permit: OwnedSemaphorePermit,
    started: Instant,
    observer: Arc<dyn AdmissionObserver>,
}

impl Drop for PendingWait {
    fn drop(&mut self) {
        self.observer.pending_finished(self.started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures::poll;

    use super::*;

    #[derive(Default)]
    struct RecordingObserver {
        admitted: Mutex<usize>,
        pending_finished: Mutex<Vec<Duration>>,
        execution_finished: Mutex<Vec<Duration>>,
    }

    impl AdmissionObserver for RecordingObserver {
        fn admitted(&self) {
            *self.admitted.lock().unwrap() += 1;
        }

        fn pending_finished(&self, duration: Duration) {
            self.pending_finished.lock().unwrap().push(duration);
        }

        fn execution_finished(&self, duration: Duration) {
            self.execution_finished.lock().unwrap().push(duration);
        }
    }

    fn limits(work: usize, pending: usize, timeout: Duration) -> AdmissionLimits {
        AdmissionLimits::new(work, pending, timeout).expect("test limits are valid")
    }

    fn controller(
        work: usize,
        pending: usize,
        timeout: Duration,
        shutdown: CancellationToken,
    ) -> (Arc<SemaphoreAdmission>, Arc<RecordingObserver>) {
        let observer = Arc::new(RecordingObserver::default());
        let controller =
            SemaphoreAdmission::new(limits(work, pending, timeout), shutdown, observer.clone());
        (controller, observer)
    }

    #[test]
    fn limits_reject_values_that_would_make_semaphore_panic() {
        let cases = [
            (
                AdmissionLimits::new(0, 1, Duration::from_secs(1)),
                "max_work_in_flight",
            ),
            (
                AdmissionLimits::new(Semaphore::MAX_PERMITS + 1, 1, Duration::from_secs(1)),
                "max_work_in_flight",
            ),
            (
                AdmissionLimits::new(1, 0, Duration::from_secs(1)),
                "max_pending",
            ),
            (
                AdmissionLimits::new(1, Semaphore::MAX_PERMITS + 1, Duration::from_secs(1)),
                "max_pending",
            ),
            (
                AdmissionLimits::new(1, 1, Duration::ZERO),
                "pending_timeout",
            ),
        ];

        for (result, field) in cases {
            let error = result.expect_err("invalid limit must be rejected");
            assert!(error.to_string().contains(field), "{error}");
        }

        AdmissionLimits::new(
            Semaphore::MAX_PERMITS,
            Semaphore::MAX_PERMITS,
            Duration::from_secs(1),
        )
        .expect("Tokio's maximum is valid");
    }

    #[tokio::test(start_paused = true)]
    async fn pending_capacity_is_bounded_and_cancellation_releases_it() {
        let (controller, observer) =
            controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        let executing = controller
            .acquire(())
            .await
            .expect("first work is admitted");
        assert_eq!(
            controller.snapshot(),
            AdmissionSnapshot {
                work_in_flight: 1,
                pending: 0,
            }
        );

        {
            let pending = controller.acquire(());
            tokio::pin!(pending);
            assert!(poll!(&mut pending).is_pending());
            assert_eq!(
                controller.snapshot(),
                AdmissionSnapshot {
                    work_in_flight: 1,
                    pending: 1,
                }
            );
            assert_eq!(
                controller
                    .acquire(())
                    .await
                    .expect_err("pending queue is full"),
                RejectionReason::QueueFull
            );
        }

        assert_eq!(controller.snapshot().pending, 0);
        assert_eq!(observer.pending_finished.lock().unwrap().len(), 1);
        drop(executing);
        assert_eq!(controller.snapshot().work_in_flight, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_removes_pending_work_and_reports_lifecycle() {
        let timeout = Duration::from_secs(5);
        let (controller, observer) = controller(1, 1, timeout, CancellationToken::new());
        let executing = controller
            .acquire(())
            .await
            .expect("first work is admitted");
        let pending = controller.acquire(());
        tokio::pin!(pending);
        assert!(poll!(&mut pending).is_pending());

        tokio::time::advance(timeout).await;
        assert_eq!(
            pending.await.expect_err("pending work must time out"),
            RejectionReason::QueueTimeout
        );
        assert_eq!(controller.snapshot().pending, 0);
        assert_eq!(observer.pending_finished.lock().unwrap().len(), 1);

        drop(executing);
        assert_eq!(*observer.admitted.lock().unwrap(), 1);
        assert_eq!(observer.execution_finished.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn shutdown_and_closed_controller_are_rejected() {
        let shutdown = CancellationToken::new();
        let (shutting_down_controller, _) =
            controller(1, 1, Duration::from_secs(1), shutdown.clone());
        shutdown.cancel();
        assert_eq!(
            shutting_down_controller
                .acquire(())
                .await
                .expect_err("shutdown rejects work"),
            RejectionReason::ShuttingDown
        );

        let (controller, _) = controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        controller.close();
        assert_eq!(
            controller
                .acquire(())
                .await
                .expect_err("closed controller rejects work"),
            RejectionReason::ControllerUnavailable
        );
    }
}
