// SPDX-FileCopyrightText: Copyright (c) 2026 MIRANTIS, INC. & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Reports a machine's LLDP neighbors to nico-api as a full snapshot, skipping
//! the RPC when the snapshot has not changed since the last successful send.
use std::time::Duration;

use ::rpc::forge::{InterfaceLldp, LldpNeighborReport};
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig, ForgeTlsClient};
use carbide_uuid::machine::MachineId;

use crate::lldp_collector::LldpNeighbor;

#[derive(thiserror::Error, Debug)]
pub enum LldpReportError {
    #[error("could not connect to the nico-api server: {0}")]
    Connect(String),
    #[error("report_lldp_neighbors gRPC call failed: {0}")]
    Rpc(String),
    #[error("report to nico-api timed out after {0:?}")]
    Timeout(Duration),
}

pub const DEFAULT_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a [`LldpReporter::report_if_changed`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOutcome {
    /// The snapshot differed from the last one sent, so it was reported.
    Sent,
    /// The snapshot matched the last one sent, so nothing was reported.
    UnchangedSkipped,
    /// The snapshot was empty (no neighbors on any interface), so nothing was
    /// reported. An empty report is never sent, to avoid reconciling away
    /// existing rows when `lldpd`/`lldpcli` is briefly unavailable.
    EmptySkipped,
}

/// Hold one instance across the poll loop so the cache persists between
/// iterations. An empty snapshot is never sent.
pub struct LldpReporter {
    machine_id: MachineId,
    api: String,
    client_config: ForgeClientConfig,
    report_timeout: Duration,
    last_sent: Option<Vec<InterfaceLldp>>,
}

impl LldpReporter {
    pub fn new(machine_id: MachineId, api: String, client_config: ForgeClientConfig) -> Self {
        Self {
            machine_id,
            api,
            client_config,
            report_timeout: DEFAULT_REPORT_TIMEOUT,
            last_sent: None,
        }
    }

    /// Overrides [`DEFAULT_REPORT_TIMEOUT`] for callers whose poll interval or
    /// tolerance for a stalled loop differs.
    #[must_use]
    pub fn with_report_timeout(mut self, report_timeout: Duration) -> Self {
        self.report_timeout = report_timeout;
        self
    }

    /// Report the given per-interface LLDP snapshot to nico-api, but only if it
    /// is non-empty and differs from the last snapshot we successfully sent.
    ///
    /// The cache is updated only after a successful send.
    pub async fn report_if_changed(
        &mut self,
        neighbors: Vec<LldpNeighbor>,
    ) -> Result<ReportOutcome, LldpReportError> {
        let interfaces = neighbors
            .into_iter()
            .map(|neighbor| InterfaceLldp {
                mac_address: neighbor.local_mac,
                lldp: Some(neighbor.switch),
            })
            .collect();

        // Split borrows: `report_snapshot` mutates `last_sent` while the send doesn't.
        Self::report_snapshot(
            &mut self.last_sent,
            self.machine_id,
            interfaces,
            self.report_timeout,
            |report| send_report(&self.api, &self.client_config, report),
        )
        .await
    }

    /// Cache logic shared by [`Self::report_if_changed`], with the send effect
    /// injected so it can be unit-tested without a live gRPC connection. `send`
    /// is invoked at most once, only when the snapshot is non-empty and differs
    /// from the last successful send.
    /// The cache is updated only after `send` succeeds.
    async fn report_snapshot<F, Fut>(
        last_sent: &mut Option<Vec<InterfaceLldp>>,
        machine_id: MachineId,
        interfaces: Vec<InterfaceLldp>,
        report_timeout: Duration,
        send: F,
    ) -> Result<ReportOutcome, LldpReportError>
    where
        F: FnOnce(LldpNeighborReport) -> Fut,
        Fut: std::future::Future<Output = Result<(), LldpReportError>>,
    {
        if interfaces.is_empty() {
            return Ok(ReportOutcome::EmptySkipped);
        }

        if last_sent.as_deref() == Some(interfaces.as_slice()) {
            return Ok(ReportOutcome::UnchangedSkipped);
        }

        let report = LldpNeighborReport {
            machine_id: Some(machine_id),
            interfaces: interfaces.clone(),
        };
        tokio::time::timeout(report_timeout, send(report))
            .await
            .map_err(|_| LldpReportError::Timeout(report_timeout))??;

        *last_sent = Some(interfaces);
        Ok(ReportOutcome::Sent)
    }
}

async fn send_report(
    api: &str,
    client_config: &ForgeClientConfig,
    report: LldpNeighborReport,
) -> Result<(), LldpReportError> {
    let mut client = ForgeTlsClient::retry_build(&ApiConfig::new(api, client_config))
        .await
        .map_err(|e| LldpReportError::Connect(e.to_string()))?;

    tracing::trace!("report_lldp_neighbors: {report:?}");
    client
        .report_lldp_neighbors(tonic::Request::new(report))
        .await
        .map_err(|e| LldpReportError::Rpc(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use ::rpc::machine_discovery::LldpSwitchData;

    use super::*;

    const TEST_REPORT_TIMEOUT: Duration = Duration::from_millis(50);

    fn iface_lldp(mac: &str, port: &str) -> InterfaceLldp {
        InterfaceLldp {
            mac_address: mac.to_string(),
            lldp: Some(LldpSwitchData {
                local_port: port.to_string(),
                ..Default::default()
            }),
        }
    }

    #[derive(Default)]
    struct MockGrpc {
        received: RefCell<Vec<LldpNeighborReport>>,
        fail: bool,
    }

    impl MockGrpc {
        fn sender(
            &self,
        ) -> impl FnOnce(LldpNeighborReport) -> std::future::Ready<Result<(), LldpReportError>> + '_
        {
            move |report| {
                self.received.borrow_mut().push(report);
                std::future::ready(if self.fail {
                    Err(LldpReportError::Rpc("mock failure".into()))
                } else {
                    Ok(())
                })
            }
        }

        fn call_count(&self) -> usize {
            self.received.borrow().len()
        }
    }

    fn machine_id() -> MachineId {
        // Any valid id works; its value is irrelevant to the cache logic.
        use std::str::FromStr;
        MachineId::from_str("fm100dsasb5dsh6e6ogogslpovne4rj82rp9jlf00qd7mcvmaadv85phk3g")
            .expect("valid test machine id")
    }

    // The first non-empty snapshot is sent; an identical follow-up snapshot is
    // NOT sent again; a changed snapshot is sent. The mock gRPC endpoint proves
    // it received exactly the reports we expect, in order. `last_sent` is the
    // cache cell `report_if_changed` threads across loop iterations.
    #[tokio::test]
    async fn unchanged_snapshot_is_not_resent() {
        let mut last_sent = None;
        let grpc = MockGrpc::default();

        let snap = vec![iface_lldp("aa:bb:cc:dd:ee:ff", "p0")];

        // First send: changed (from empty cache) -> Sent, one RPC.
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReportOutcome::Sent);
        assert_eq!(grpc.call_count(), 1, "first snapshot should be sent");

        // Identical snapshot: cached -> skipped, no additional RPC.
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReportOutcome::UnchangedSkipped);
        assert_eq!(
            grpc.call_count(),
            1,
            "identical snapshot must not trigger another RPC"
        );

        // Changed snapshot: differs -> Sent, one more RPC.
        let changed = vec![
            iface_lldp("aa:bb:cc:dd:ee:ff", "p0"),
            iface_lldp("aa:bb:cc:dd:ee:aa", "p1"),
        ];
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            changed.clone(),
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReportOutcome::Sent);
        assert_eq!(grpc.call_count(), 2, "changed snapshot should be sent");

        let received = grpc.received.borrow();
        assert_eq!(received[0].interfaces, snap);
        assert_eq!(received[1].interfaces, changed);
    }

    // An empty snapshot is never sent and doesn't change the cache.
    #[tokio::test]
    async fn empty_snapshot_is_skipped_and_preserves_cache() {
        let mut last_sent = None;
        let grpc = MockGrpc::default();
        let snap = vec![iface_lldp("aa:bb:cc:dd:ee:ff", "p0")];

        LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(grpc.call_count(), 1);

        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            vec![],
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReportOutcome::EmptySkipped);
        assert_eq!(grpc.call_count(), 1, "empty snapshot must not be sent");

        // Cache survived the empty poll: the original snapshot is still "unchanged".
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            grpc.sender(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReportOutcome::UnchangedSkipped);
        assert_eq!(grpc.call_count(), 1);
    }

    // A failed send must NOT update the cache, so the same snapshot is retried
    // (and sent) on the next call rather than being suppressed as "unchanged".
    #[tokio::test]
    async fn failed_send_is_retried_next_time() {
        let mut last_sent = None;
        let snap = vec![iface_lldp("aa:bb:cc:dd:ee:ff", "p0")];

        let failing = MockGrpc {
            fail: true,
            ..Default::default()
        };
        let err = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            failing.sender(),
        )
        .await;
        assert!(err.is_err(), "send failure should propagate");
        assert_eq!(failing.call_count(), 1);

        // Cache was not updated, so the retry actually sends.
        let ok = MockGrpc::default();
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            ok.sender(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReportOutcome::Sent,
            "unchanged after a failed send must retry"
        );
        assert_eq!(ok.call_count(), 1);
    }

    // A send that never resolves is abandoned after the configured timeout, and
    // must leave the cache untouched so the snapshot is retried rather than
    // suppressed as "unchanged". `start_paused` lets the runtime jump the clock
    // to the timer deadline, so the test does not actually wait.
    #[tokio::test(start_paused = true)]
    async fn timed_out_send_is_retried_next_time() {
        let mut last_sent = None;
        let snap = vec![iface_lldp("aa:bb:cc:dd:ee:ff", "p0")];

        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            |_report| std::future::pending(),
        )
        .await;
        assert!(
            matches!(outcome, Err(LldpReportError::Timeout(timeout)) if timeout == TEST_REPORT_TIMEOUT),
            "a send that never resolves must time out, got {outcome:?}"
        );

        // Cache was not updated, so the retry actually sends.
        let ok = MockGrpc::default();
        let outcome = LldpReporter::report_snapshot(
            &mut last_sent,
            machine_id(),
            snap.clone(),
            TEST_REPORT_TIMEOUT,
            ok.sender(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReportOutcome::Sent,
            "unchanged after a timed-out send must retry"
        );
        assert_eq!(ok.call_count(), 1);
    }
}
