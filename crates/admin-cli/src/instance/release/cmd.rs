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

use std::future::Future;
use std::time::Duration;

use ::rpc::forge::InstanceReleaseRequest;
use carbide_uuid::instance::InstanceId;

use super::args::Args;
use crate::cfg::runtime::RuntimeContext;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

/// gRPC metadata key the API attaches to a `RESOURCE_EXHAUSTED` admission
/// rejection, carrying the advertised backoff in whole milliseconds. Must match
/// `GRPC_RETRY_PUSHBACK_HEADER` in `api-core/src/admission/mod.rs`.
const ADMISSION_RETRY_PUSHBACK_HEADER: &str = "grpc-retry-pushback-ms";
/// Per-instance attempt cap so a genuinely stuck condition cannot hang forever.
const MAX_RELEASE_ATTEMPTS: usize = 8;
/// Per-instance cumulative backoff cap; give up on an instance past this.
const MAX_TOTAL_BACKOFF: Duration = Duration::from_secs(120);
/// Backoff used when the server omits an (unexpected) parseable pushback value.
const DEFAULT_ADMISSION_BACKOFF: Duration = Duration::from_secs(5);
/// Bounds mirroring the server's own advertised range in `admission/retry.rs`.
const MIN_ADMISSION_BACKOFF: Duration = Duration::from_secs(1);
const MAX_ADMISSION_BACKOFF: Duration = Duration::from_secs(30);
/// Batch-wide circuit breaker: once this many instances in a row exhaust their
/// per-instance admission retry budget, the backend is saturated for the whole
/// batch, so stop starting new instances instead of letting each one burn its
/// full budget. Per-instance backoff is bounded to ~120s, so without this a
/// 4,500-instance batch against a persistently saturated backend could grind
/// for days (observed live: ~20 min of continuous per-instance retries).
const MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS: usize = 3;

/// Parses the server-advertised retry delay from a rejection's metadata.
fn admission_retry_delay(status: &tonic::Status) -> Option<Duration> {
    let millis = status
        .metadata()
        .get(ADMISSION_RETRY_PUSHBACK_HEADER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;
    Some(Duration::from_millis(millis))
}

/// Runs a single-instance release, retrying only `RESOURCE_EXHAUSTED` admission
/// rejections by honoring the server's advertised `grpc-retry-pushback-ms`
/// backoff. Retries are bounded by attempt count and cumulative backoff; any
/// other error surfaces immediately so real failures are not masked.
///
/// Motivation: a live 4,500-host scale-test release stranded 1,667/4,499
/// instances because the batch loop aborted on the first admission rejection —
/// a normal per-client rate limit — instead of backing off and resubmitting.
async fn release_with_retry<F, Fut>(mut attempt: F) -> Result<(), tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), tonic::Status>>,
{
    let mut total_backoff = Duration::ZERO;
    for attempt_number in 1..=MAX_RELEASE_ATTEMPTS {
        match attempt().await {
            Ok(()) => return Ok(()),
            Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                if attempt_number == MAX_RELEASE_ATTEMPTS {
                    return Err(status);
                }
                let delay = admission_retry_delay(&status)
                    .unwrap_or(DEFAULT_ADMISSION_BACKOFF)
                    .clamp(MIN_ADMISSION_BACKOFF, MAX_ADMISSION_BACKOFF);
                if total_backoff.saturating_add(delay) > MAX_TOTAL_BACKOFF {
                    return Err(status);
                }
                total_backoff = total_backoff.saturating_add(delay);
                tokio::time::sleep(delay).await;
            }
            Err(status) => return Err(status),
        }
    }
    unreachable!("loop returns on the final attempt")
}

/// Result of releasing a batch of instances.
struct BatchReleaseOutcome {
    released: usize,
    /// Instances that were attempted (with retries) but ultimately failed.
    failures: Vec<(InstanceId, tonic::Status)>,
    /// Instances skipped because the batch-wide circuit breaker tripped.
    not_attempted: Vec<InstanceId>,
}

/// Releases each instance in turn, retrying admission rejections per instance and
/// collecting failures so one stuck instance cannot strand the rest. Trips a
/// batch-wide circuit breaker after [`MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS`]
/// instances in a row exhaust their admission budget, leaving the remainder
/// unattempted rather than grinding through every one at full backoff.
///
/// `release_one` is injected so the batch/continuation logic is exercised
/// directly in tests without a live gRPC client.
async fn release_batch<F, Fut>(
    instance_ids: Vec<InstanceId>,
    mut release_one: F,
) -> BatchReleaseOutcome
where
    F: FnMut(InstanceId) -> Fut,
    Fut: Future<Output = Result<(), tonic::Status>>,
{
    let mut released = 0usize;
    let mut failures = Vec::new();
    let mut not_attempted = Vec::new();
    let mut consecutive_admission_exhaustions = 0usize;

    let mut remaining = instance_ids.into_iter();
    while let Some(instance_id) = remaining.next() {
        match release_with_retry(|| release_one(instance_id)).await {
            Ok(()) => {
                released += 1;
                consecutive_admission_exhaustions = 0;
            }
            Err(status) => {
                let admission_exhausted = status.code() == tonic::Code::ResourceExhausted;
                tracing::error!(
                    instance_id = %instance_id,
                    code = ?status.code(),
                    "Failed to release instance: {}",
                    status.message()
                );
                failures.push((instance_id, status));

                if admission_exhausted {
                    consecutive_admission_exhaustions += 1;
                    if consecutive_admission_exhaustions >= MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS {
                        not_attempted.extend(remaining);
                        break;
                    }
                } else {
                    consecutive_admission_exhaustions = 0;
                }
            }
        }
    }

    BatchReleaseOutcome {
        released,
        failures,
        not_attempted,
    }
}

pub(super) async fn release(
    api_client: &ApiClient,
    release_request: Args,
    ctx: &RuntimeContext,
) -> CarbideCliResult<()> {
    ctx.assert_cloud_unsafe_op_message()?;

    let mut instance_ids: Vec<InstanceId> = Vec::new();

    match (
        release_request.instance,
        release_request.machine,
        release_request.label_key,
    ) {
        (Some(instance_id), _, _) => instance_ids.push(
            uuid::Uuid::parse_str(&instance_id)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?
                .into(),
        ),
        (_, Some(machine_id), _) => {
            let instances = api_client
                .0
                .find_instance_by_machine_id(machine_id)
                .await?
                .instances;
            let Some(instance_id) = instances.into_iter().next().and_then(|i| i.id) else {
                return Err(CarbideCliError::GenericError(
                    "No instances assigned to that machine".to_string(),
                ));
            };
            instance_ids.push(instance_id);
        }
        (_, _, Some(key)) => {
            let instances = api_client
                .get_all_instances(
                    None,
                    None,
                    Some(key),
                    release_request.label_value,
                    None,
                    ctx.config.page_size,
                )
                .await?;
            if instances.instances.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "No instances with the passed label.key exist".to_string(),
                ));
            }
            instance_ids = instances
                .instances
                .iter()
                .filter_map(|instance| instance.id)
                .collect();
        }
        _ => {}
    };
    let total = instance_ids.len();

    let outcome = release_batch(instance_ids, |instance_id| async move {
        api_client
            .0
            .release_instance(InstanceReleaseRequest {
                id: Some(instance_id),
                issue: None,
                is_repair_tenant: None,
                delete_attribution: None,
            })
            .await
            .map(|_| ())
    })
    .await;

    let BatchReleaseOutcome {
        released,
        failures,
        not_attempted,
    } = outcome;

    if failures.is_empty() && not_attempted.is_empty() {
        tracing::info!("Released {total} instance(s).");
        return Ok(());
    }

    tracing::error!(
        "Released {released}/{total} instance(s); {} failed, {} not attempted:",
        failures.len(),
        not_attempted.len()
    );
    for (instance_id, status) in &failures {
        tracing::error!(
            instance_id = %instance_id,
            "  {} ({:?})",
            status.message(),
            status.code()
        );
    }
    if !not_attempted.is_empty() {
        tracing::error!(
            "Stopped after {MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS} consecutive admission \
             exhaustions (backend saturated); {} instance(s) not attempted.",
            not_attempted.len()
        );
    }
    Err(CarbideCliError::GenericError(format!(
        "release incomplete: {} failed, {} not attempted of {total} instance(s) (see logs above)",
        failures.len(),
        not_attempted.len()
    )))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use tonic::metadata::MetadataValue;

    use super::*;

    fn exhausted(pushback_millis: u64) -> tonic::Status {
        let mut status = tonic::Status::resource_exhausted("API admission capacity exhausted");
        status.metadata_mut().insert(
            ADMISSION_RETRY_PUSHBACK_HEADER,
            MetadataValue::try_from(pushback_millis.to_string().as_str()).unwrap(),
        );
        status
    }

    #[test]
    fn parses_advertised_pushback_delay() {
        assert_eq!(
            admission_retry_delay(&exhausted(7_000)),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            admission_retry_delay(&tonic::Status::resource_exhausted("no header")),
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_after_advertised_delay_then_succeeds() {
        let attempts = Cell::new(0);
        let start = tokio::time::Instant::now();

        let result = release_with_retry(|| {
            let attempt = attempts.get() + 1;
            attempts.set(attempt);
            async move {
                if attempt < 3 {
                    Err(exhausted(7_000))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(attempts.get(), 3);
        // Two rejections, each honoring the advertised 7s pushback.
        assert_eq!(start.elapsed(), Duration::from_secs(14));
    }

    #[tokio::test(start_paused = true)]
    async fn retries_are_bounded_by_attempt_cap() {
        let attempts = Cell::new(0);

        let result = release_with_retry(|| {
            attempts.set(attempts.get() + 1);
            async move { Err::<(), _>(exhausted(1_000)) }
        })
        .await;

        assert_eq!(result.unwrap_err().code(), tonic::Code::ResourceExhausted);
        assert_eq!(attempts.get(), MAX_RELEASE_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn non_admission_errors_surface_without_retry() {
        let attempts = Cell::new(0);

        let result = release_with_retry(|| {
            attempts.set(attempts.get() + 1);
            async move { Err::<(), _>(tonic::Status::not_found("gone")) }
        })
        .await;

        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
        assert_eq!(attempts.get(), 1);
    }

    fn instance_ids(count: u128) -> Vec<InstanceId> {
        (1..=count)
            .map(|n| uuid::Uuid::from_u128(n).into())
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn batch_continues_past_a_failed_instance() {
        // Exercises the real `release_batch` path: the middle instance fails
        // (non-admission), yet the rest still get attempted and released.
        let ids = instance_ids(3);
        let stuck = ids[1];

        let outcome = release_batch(ids, |instance_id| async move {
            if instance_id == stuck {
                Err(tonic::Status::not_found("gone"))
            } else {
                Ok(())
            }
        })
        .await;

        assert_eq!(outcome.released, 2);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].0, stuck);
        assert!(outcome.not_attempted.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn batch_circuit_breaker_stops_when_backend_stays_saturated() {
        // Every instance is admission-exhausted: the breaker must stop starting
        // new instances after the consecutive-exhaustion threshold.
        let ids = instance_ids(10);

        let outcome = release_batch(ids, |_instance_id| async move { Err(exhausted(1_000)) }).await;

        assert_eq!(outcome.released, 0);
        assert_eq!(
            outcome.failures.len(),
            MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS
        );
        assert_eq!(
            outcome.not_attempted.len(),
            10 - MAX_CONSECUTIVE_ADMISSION_EXHAUSTIONS
        );
    }

    #[tokio::test(start_paused = true)]
    async fn batch_circuit_breaker_resets_on_progress() {
        // A success between admission exhaustions resets the consecutive count,
        // so transient blips never trip the breaker and the whole batch runs.
        let ids = instance_ids(10);
        // Fail every other instance so admission exhaustions never occur back to
        // back (fail, ok, fail, ok, ...).
        let failing: Vec<InstanceId> = ids.iter().copied().step_by(2).collect();

        let outcome = release_batch(ids, move |instance_id| {
            let should_fail = failing.contains(&instance_id);
            async move {
                if should_fail {
                    Err(exhausted(1_000))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(
            outcome.not_attempted.is_empty(),
            "breaker must not trip when successes interleave failures"
        );
        assert_eq!(outcome.released, 5);
        assert_eq!(outcome.failures.len(), 5);
    }
}
