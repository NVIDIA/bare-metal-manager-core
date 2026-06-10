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
use std::sync::Arc;

use super::client::{RestClient, UsernamePassword};
use crate::HealthError;
use crate::bmc::{CREDENTIAL_REFRESH_TIMEOUT, CredentialProvider, is_auth_error};
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NvueRestConfig;
use crate::endpoint::{BmcAddr, BmcCredentials, BmcEndpoint, EndpointMetadata};
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

const COLLECTOR_NAME: &str = "nvue_rest";

fn system_health_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("OK") => 1.0,
        Some("Not OK") => 2.0,
        _ => 0.0,
    }
}

fn partition_health_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("healthy") => 1.0,
        Some("degraded_bandwidth") => 2.0,
        Some("degraded") => 3.0,
        Some("unhealthy") => 4.0,
        _ => 0.0,
    }
}

fn app_status_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("ok") => 1.0,
        Some("not ok") => 2.0,
        _ => 0.0,
    }
}

/// code "0" means no issue; any other opcode indicates a problem
fn diagnostic_opcode_to_f64(code: &str) -> f64 {
    match code {
        "0" => 0.0,
        _ => 1.0,
    }
}

pub struct NvueRestCollectorConfig {
    pub rest_config: NvueRestConfig,
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub credential_provider: Arc<dyn CredentialProvider>,
}

pub struct NvueRestCollector {
    client: RestClient,
    switch_id: String,
    event_context: EventContext,
    data_sink: Option<Arc<dyn DataSink>>,
    addr: BmcAddr,
    provider: Arc<dyn CredentialProvider>,
}

impl PeriodicCollector<crate::bmc::BmcClient> for NvueRestCollector {
    type Config = NvueRestCollectorConfig;

    fn new_runner(
        _bmc: Arc<crate::bmc::BmcClient>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let switch_id = match &endpoint.metadata {
            Some(EndpointMetadata::Switch(s)) => s.serial.clone(),
            _ => endpoint.addr.mac.to_string(),
        };
        let switch_ip = endpoint.addr.ip.to_string();
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), COLLECTOR_NAME);

        let rest_cfg = &config.rest_config;
        // self_signed_tls is always true -- TLS cert provisioning on switches is not yet implemented
        let client = RestClient::new(
            switch_id.clone(),
            &switch_ip,
            rest_cfg.request_timeout,
            true,
            rest_cfg.paths.clone(),
        )?;

        Ok(Self {
            client,
            switch_id,
            event_context,
            data_sink: config.data_sink,
            addr: endpoint.addr.clone(),
            provider: config.credential_provider,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        if !self.client.has_credentials()
            && let Err(error) = self.refresh_rest_credentials().await
        {
            tracing::warn!(
                ?error,
                switch_id = %self.switch_id,
                "nvue_rest: skipping iteration — credential fetch failed"
            );
            return Ok(IterationResult {
                refresh_triggered: false,
                entity_count: Some(0),
                fetch_failures: 1,
            });
        }

        self.emit_event(CollectorEvent::MetricCollectionStart);
        let mut entity_count = 0usize;
        let mut fetch_failures = 0usize;
        let mut saw_auth_failure = false;

        match self.client.get_system_health().await {
            Ok(Some(health)) => {
                let value = system_health_to_f64(health.status.as_deref());
                self.emit_metric("system_health", None, value, "state", vec![]);
                entity_count += 1;
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect system health"
                );
            }
        }

        match self.client.get_cluster_apps().await {
            Ok(Some(apps)) => {
                for (name, app) in &apps {
                    let value = app_status_to_f64(app.status.as_deref());
                    self.emit_metric(
                        "cluster_app",
                        Some(name),
                        value,
                        "state",
                        vec![(Cow::Borrowed("app_name"), name.clone())],
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect cluster apps"
                );
            }
        }

        match self.client.get_sdn_partitions().await {
            Ok(Some(partitions)) => {
                for (part_id, partition) in &partitions {
                    let part_name = partition.name.as_deref().unwrap_or(part_id);
                    let health_value = partition_health_to_f64(partition.health.as_deref());
                    let gpu_count = partition.num_gpus.unwrap_or(0) as f64;

                    let partition_labels = vec![
                        (Cow::Borrowed("partition_id"), part_id.clone()),
                        (Cow::Borrowed("partition_name"), part_name.to_string()),
                    ];
                    self.emit_metric(
                        "partition_health",
                        Some(part_id),
                        health_value,
                        "state",
                        partition_labels.clone(),
                    );
                    self.emit_metric(
                        "partition_gpu",
                        Some(part_id),
                        gpu_count,
                        "count",
                        partition_labels,
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect SDN partitions"
                );
            }
        }

        match self.client.get_link_diagnostics().await {
            Ok(diagnostics) => {
                for diag in &diagnostics {
                    let value = diagnostic_opcode_to_f64(&diag.code);
                    self.emit_metric(
                        "link_diagnostic",
                        Some(&format!("{}:{}", diag.interface, diag.code)),
                        value,
                        "state",
                        vec![
                            (Cow::Borrowed("interface_name"), diag.interface.clone()),
                            (Cow::Borrowed("opcode"), diag.code.clone()),
                            (Cow::Borrowed("diagnostic_status"), diag.status.clone()),
                        ],
                    );
                    entity_count += 1;
                }
            }
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect link diagnostics"
                );
            }
        }

        if saw_auth_failure {
            tracing::warn!(
                switch_id = %self.switch_id,
                "nvue_rest: auth failure observed, clearing cached credentials"
            );
            self.client.clear_credentials();
        }

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        tracing::debug!(
            switch_id = %self.switch_id,
            entity_count,
            "nvue_rest: collection iteration complete"
        );

        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: Some(entity_count),
            fetch_failures,
        })
    }

    fn collector_type(&self) -> &'static str {
        COLLECTOR_NAME
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl NvueRestCollector {
    async fn refresh_rest_credentials(&self) -> Result<(), HealthError> {
        let creds = tokio::time::timeout(
            CREDENTIAL_REFRESH_TIMEOUT,
            self.provider.fetch_credentials(&self.addr),
        )
        .await
        .map_err(|_elapsed| {
            HealthError::GenericError(format!(
                "Timed out after {}s fetching NVUE REST credentials",
                CREDENTIAL_REFRESH_TIMEOUT.as_secs(),
            ))
        })??;
        match creds {
            BmcCredentials::UsernamePassword { username, password } => {
                self.client
                    .set_credentials(UsernamePassword { username, password });
                Ok(())
            }
            _ => Err(HealthError::GenericError(
                "NVUE REST collector requires username/password credentials".to_string(),
            )),
        }
    }

    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    fn emit_metric(
        &self,
        metric_type: &str,
        entity_qualifier: Option<&str>,
        value: f64,
        unit: &str,
        labels: Vec<(Cow<'static, str>, String)>,
    ) {
        let key = match entity_qualifier {
            Some(q) => {
                let mut k = String::with_capacity(metric_type.len() + 1 + q.len());
                k.push_str(metric_type);
                k.push(':');
                k.push_str(q);
                k
            }
            None => metric_type.to_string(),
        };

        self.emit_event(CollectorEvent::Metric(
            MetricSample {
                key,
                name: COLLECTOR_NAME.to_string(),
                metric_type: metric_type.to_string(),
                unit: unit.to_string(),
                value,
                labels,
                context: None,
            }
            .into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use mac_address::MacAddress;

    use super::*;
    use crate::bmc::BoxFuture;
    use crate::config::NvueRestPaths;

    #[test]
    fn test_system_health_mapping() {
        assert_eq!(system_health_to_f64(Some("OK")), 1.0);
        assert_eq!(system_health_to_f64(Some("Not OK")), 2.0);
        assert_eq!(system_health_to_f64(None), 0.0);
        assert_eq!(system_health_to_f64(Some("unknown_value")), 0.0);
    }

    #[test]
    fn test_partition_health_mapping() {
        assert_eq!(partition_health_to_f64(Some("unknown")), 0.0);
        assert_eq!(partition_health_to_f64(Some("healthy")), 1.0);
        assert_eq!(partition_health_to_f64(Some("degraded_bandwidth")), 2.0);
        assert_eq!(partition_health_to_f64(Some("degraded")), 3.0);
        assert_eq!(partition_health_to_f64(Some("unhealthy")), 4.0);
        assert_eq!(partition_health_to_f64(None), 0.0);
    }

    #[test]
    fn test_app_status_mapping() {
        assert_eq!(app_status_to_f64(Some("ok")), 1.0);
        assert_eq!(app_status_to_f64(Some("not ok")), 2.0);
        assert_eq!(app_status_to_f64(None), 0.0);
        assert_eq!(app_status_to_f64(Some("other")), 0.0);
    }

    #[test]
    fn test_diagnostic_opcode_mapping() {
        assert_eq!(diagnostic_opcode_to_f64("0"), 0.0);
        assert_eq!(diagnostic_opcode_to_f64("2"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("1024"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("57"), 1.0);
    }

    struct ScriptedProvider {
        calls: AtomicUsize,
        // Each call pops the front of this queue; an empty queue yields an
        // error. `HealthError` is not `Clone`, so we store and consume by
        // value rather than indexing + `.cloned()`.
        responses: StdMutex<std::collections::VecDeque<Result<BmcCredentials, HealthError>>>,
    }

    impl ScriptedProvider {
        fn new(responses: Vec<Result<BmcCredentials, HealthError>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                responses: StdMutex::new(responses.into_iter().collect()),
            })
        }
    }

    impl CredentialProvider for ScriptedProvider {
        fn fetch_credentials<'a>(
            &'a self,
            _endpoint: &'a BmcAddr,
        ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(HealthError::GenericError(
                        "scripted provider exhausted".to_string(),
                    ))
                });
            Box::pin(async move { response })
        }
    }

    fn test_addr() -> BmcAddr {
        BmcAddr {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: Some(443),
            mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
        }
    }

    fn paths_all_disabled() -> NvueRestPaths {
        NvueRestPaths {
            system_health_enabled: false,
            cluster_apps_enabled: false,
            sdn_partitions_enabled: false,
            interfaces_enabled: false,
        }
    }

    fn collector_with_provider(provider: Arc<dyn CredentialProvider>) -> NvueRestCollector {
        let addr = test_addr();
        let client = RestClient::new(
            "test-switch".to_string(),
            &addr.ip.to_string(),
            Duration::from_millis(10),
            true,
            paths_all_disabled(),
        )
        .expect("rest client builds");

        let event_context = EventContext {
            endpoint_key: "test-switch".to_string(),
            addr: addr.clone(),
            collector_type: COLLECTOR_NAME,
            metadata: None,
            rack_id: None,
        };

        NvueRestCollector {
            client,
            switch_id: "test-switch".to_string(),
            event_context,
            data_sink: None,
            addr,
            provider,
        }
    }

    #[tokio::test]
    async fn first_iteration_lazy_fetches_credentials_then_runs() {
        let provider = ScriptedProvider::new(vec![Ok(BmcCredentials::UsernamePassword {
            username: "admin".to_string(),
            password: Some("hunter2".to_string()),
        })]);
        let mut collector = collector_with_provider(provider.clone());

        assert!(
            !collector.client.has_credentials(),
            "client must start credential-less so sharded-out endpoints never trigger a fetch"
        );

        let result = collector
            .run_iteration()
            .await
            .expect("iteration returns Ok even when all paths are disabled");

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(collector.client.has_credentials());
        assert_eq!(
            result.fetch_failures, 0,
            "all four paths disabled → no HTTP, no failures"
        );
        // Subsequent iterations reuse the already-installed credentials.
        collector
            .run_iteration()
            .await
            .expect("second iteration ok");
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "credential provider must not be re-hit while creds are still valid"
        );
    }

    #[tokio::test]
    async fn iteration_is_skipped_when_credential_fetch_fails_and_recovers_next_time() {
        let provider = ScriptedProvider::new(vec![
            Err(HealthError::GenericError("forge unavailable".to_string())),
            Ok(BmcCredentials::UsernamePassword {
                username: "admin".to_string(),
                password: None,
            }),
        ]);
        let mut collector = collector_with_provider(provider.clone());

        let first = collector.run_iteration().await.expect("first iteration ok");
        assert_eq!(first.fetch_failures, 1, "credential fetch failure surfaces");
        assert!(!first.refresh_triggered);
        assert!(
            !collector.client.has_credentials(),
            "failed fetch must NOT install bogus credentials"
        );

        let second = collector
            .run_iteration()
            .await
            .expect("second iteration ok");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert!(collector.client.has_credentials());
        assert_eq!(
            second.fetch_failures, 0,
            "second iteration recovers — credentials now present, no GETs to fail"
        );
    }

    #[tokio::test]
    async fn refresh_rejects_session_token_credentials() {
        let provider = ScriptedProvider::new(vec![Ok(BmcCredentials::SessionToken {
            token: "irrelevant".to_string(),
        })]);
        let collector = collector_with_provider(provider);

        let error = collector
            .refresh_rest_credentials()
            .await
            .expect_err("session-token credentials are not usable for NVUE basic auth");
        match error {
            HealthError::GenericError(msg) => assert!(
                msg.contains("requires username/password"),
                "expected explicit message, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_rest_credentials_respects_timeout() {
        // Mirrors the `BmcClient::refresh_credentials_respects_timeout`
        // contract on the NVUE REST side: a hung Forge call must not block
        // the collector's iteration loop past `CREDENTIAL_REFRESH_TIMEOUT`.
        struct HangingProvider;
        impl CredentialProvider for HangingProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                Box::pin(std::future::pending())
            }
        }

        let collector = Arc::new(collector_with_provider(Arc::new(HangingProvider)));
        let refresh_collector = collector.clone();
        let refresh =
            tokio::spawn(async move { refresh_collector.refresh_rest_credentials().await });

        // Sleep just past the timeout so the tokio timer fires.
        tokio::time::advance(CREDENTIAL_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        let result = refresh.await.expect("task joined");
        let error = result.expect_err("hanging provider must surface as timeout");
        match error {
            HealthError::GenericError(msg) => assert!(
                msg.contains("Timed out"),
                "expected timeout message, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_password() {
        let creds = UsernamePassword {
            username: "admin".to_string(),
            password: Some("hunter2".to_string()),
        };
        let rendered = format!("{creds:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug must not leak the password; got: {rendered}"
        );
        assert!(rendered.contains("admin"));
        assert!(rendered.contains("<redacted>"));

        let no_password = UsernamePassword {
            username: "admin".to_string(),
            password: None,
        };
        let rendered = format!("{no_password:?}");
        assert!(
            !rendered.contains("<redacted>"),
            "missing password must not show as redacted; got: {rendered}"
        );
    }
}
