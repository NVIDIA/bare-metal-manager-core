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
use std::time::Duration;

use carbide_instrument::{Event, LabelValue};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::time::sleep;

const TIME_BUCKETS: &[f64; 11] = &[
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0,
];

const SIZE_BUCKETS: &[f64; 9] = &[
    100.0,
    1000.0,
    10000.0,
    100000.0,
    1000000.0,
    10000000.0,
    100000000.0,
    1000000000.0,
    10000000000.0,
];

pub(crate) fn setup_prometheus() -> PrometheusHandle {
    let prometheus_builder = PrometheusBuilder::new()
        .add_global_label("system", "carbide-pxe")
        .add_global_label("build_version", carbide_version::v!(build_version))
        .add_global_label("build_date", carbide_version::v!(build_date))
        .add_global_label("rust_version", carbide_version::v!(rust_version))
        .add_global_label("build_hostname", carbide_version::v!(build_hostname))
        .set_buckets_for_metric(
            Matcher::Suffix("duration_seconds".to_string()),
            TIME_BUCKETS,
        )
        .expect("couldn't set prometheus buckets?")
        .set_buckets_for_metric(Matcher::Suffix("size_bytes".to_string()), SIZE_BUCKETS)
        .expect("couldn't set prometheus buckets?");

    let prometheus_handle = prometheus_builder
        .install_recorder()
        .expect("unable to install recorder?");

    let handle_clone = prometheus_handle.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        handle_clone.run_upkeep();
    });

    prometheus_handle
}

/// The boot-path endpoint an outcome describes, as a bounded metric label:
/// the two iPXE script routes plus the cloud-init route family
/// (user-data, meta-data, vendor-data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum BootEndpoint {
    Whoami,
    Boot,
    CloudInit,
}

/// How a boot-path request resolved, as a bounded metric label. Every
/// non-`Ok` variant is a response the machine receives as an error script
/// or generic error template over HTTP 200 -- this label is what makes
/// those outcomes visible, since the status-code metrics cannot see them.
/// Requests rejected before a handler runs (a malformed `buildarch`, an
/// upstream failure inside the `Machine` extractor) return real 4xx codes
/// the `http_*` metrics already count; only `architecture_not_found` is
/// also emitted from its extractor, because a bad architecture is a boot
/// outcome operators watch for. `upstream_api_error` is therefore
/// structurally boot-only. `ok` means the request resolved to a servable
/// response; a template that later fails to render returns a real 5xx the
/// `http_*` metrics count, which is outside this metric's HTTP-200 scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum OutcomeReason {
    Ok,
    ArchitectureNotFound,
    InterfaceNotFound,
    InstructionsEmpty,
    MetadataNotFound,
    UpstreamApiError,
}

/// A boot-path request resolved to a servable response -- the real script
/// or an error template. Metric-only: the existing stderr lines on the
/// failure paths stay as they are, and the rate is the signal.
#[derive(Event)]
#[event(
    name = "carbide_pxe_boot_outcomes_total",
    component = "carbide-pxe",
    log = off,
    metric = counter,
    describe = "Number of PXE boot-path outcomes served, by endpoint and reason."
)]
pub(crate) struct PxeBootOutcome {
    #[label]
    pub endpoint: BootEndpoint,
    #[label]
    pub reason: OutcomeReason,
}

#[cfg(test)]
mod tests {
    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};

    use super::*;

    /// The label vocabulary is the dashboard contract: each variant renders
    /// as its snake_case name, byte for byte.
    #[test]
    fn label_values_render_as_snake_case() {
        check_values(
            [
                Check {
                    scenario: "whoami endpoint",
                    input: BootEndpoint::Whoami.label_value(),
                    expect: "whoami".to_string(),
                },
                Check {
                    scenario: "boot endpoint",
                    input: BootEndpoint::Boot.label_value(),
                    expect: "boot".to_string(),
                },
                Check {
                    scenario: "cloud-init endpoint",
                    input: BootEndpoint::CloudInit.label_value(),
                    expect: "cloud_init".to_string(),
                },
                Check {
                    scenario: "ok",
                    input: OutcomeReason::Ok.label_value(),
                    expect: "ok".to_string(),
                },
                Check {
                    scenario: "architecture not found",
                    input: OutcomeReason::ArchitectureNotFound.label_value(),
                    expect: "architecture_not_found".to_string(),
                },
                Check {
                    scenario: "interface not found",
                    input: OutcomeReason::InterfaceNotFound.label_value(),
                    expect: "interface_not_found".to_string(),
                },
                Check {
                    scenario: "instructions empty",
                    input: OutcomeReason::InstructionsEmpty.label_value(),
                    expect: "instructions_empty".to_string(),
                },
                Check {
                    scenario: "upstream API error",
                    input: OutcomeReason::UpstreamApiError.label_value(),
                    expect: "upstream_api_error".to_string(),
                },
                Check {
                    scenario: "render failure",
                    input: OutcomeReason::MetadataNotFound.label_value(),
                    expect: "metadata_not_found".to_string(),
                },
            ],
            |value| value.to_string(),
        );
    }

    /// Each emit moves exactly its label pair's series, and none of them
    /// builds a log line -- the event is declared `log = off` because this
    /// binary has no tracing subscriber and its stderr lines stay untouched.
    #[test]
    fn boot_outcomes_count_per_label_without_logging() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::Whoami,
                reason: OutcomeReason::Ok,
            });
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::Boot,
                reason: OutcomeReason::UpstreamApiError,
            });
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::Boot,
                reason: OutcomeReason::UpstreamApiError,
            });
            emit(PxeBootOutcome {
                endpoint: BootEndpoint::CloudInit,
                reason: OutcomeReason::MetadataNotFound,
            });
        });

        assert!(
            logs.is_empty(),
            "log = off must not construct any log line, got {logs:?}"
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "whoami"), ("reason", "ok")],
            ),
            1.0,
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "boot"), ("reason", "upstream_api_error")],
            ),
            2.0,
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "cloud_init"), ("reason", "metadata_not_found")],
            ),
            1.0,
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_pxe_boot_outcomes_total",
                &[("endpoint", "boot"), ("reason", "ok")],
            ),
            0.0,
            "an untouched label pair must not move",
        );
    }
}
