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

use std::time::Instant;

use super::DowngradeReason;
use crate::HealthError;
use crate::config::AutoModeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    SseNotAvailable,
    Transient,
}

impl FailureKind {
    pub(crate) fn classify(err: &HealthError) -> Self {
        match err {
            HealthError::SseNotAvailable(_) => Self::SseNotAvailable,
            _ => Self::Transient,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetDecision {
    Continue,
    Downgrade(DowngradeReason),
}

#[derive(Debug)]
pub(crate) struct AutoFailureBudget {
    cfg: AutoModeConfig,
    sse_not_available_count: u32,
    window_start: Instant,
    window_failure_count: u32,
}

impl AutoFailureBudget {
    pub(crate) fn new(cfg: AutoModeConfig, now: Instant) -> Self {
        Self {
            cfg,
            sse_not_available_count: 0,
            window_start: now,
            window_failure_count: 0,
        }
    }

    pub(crate) fn record(&mut self, kind: FailureKind, now: Instant) -> BudgetDecision {
        match kind {
            FailureKind::SseNotAvailable => {
                self.sse_not_available_count = self.sse_not_available_count.saturating_add(1);
                if self.sse_not_available_count >= self.cfg.sse_not_available_threshold {
                    BudgetDecision::Downgrade(DowngradeReason::SseNotAvailable)
                } else {
                    BudgetDecision::Continue
                }
            }
            FailureKind::Transient => {
                if now.saturating_duration_since(self.window_start)
                    >= self.cfg.connect_failure_window
                {
                    self.window_start = now;
                    self.window_failure_count = 0;
                }
                self.window_failure_count = self.window_failure_count.saturating_add(1);
                if self.window_failure_count >= self.cfg.connect_failure_threshold {
                    BudgetDecision::Downgrade(DowngradeReason::ConnectFailureBudgetExhausted)
                } else {
                    BudgetDecision::Continue
                }
            }
        }
    }

    // wipes transient window on successful connect so flaps don't pile up,
    // but sse-not-available count is intentionally kept -- that's terminal.
    pub(crate) fn reset_transient(&mut self, now: Instant) {
        self.window_start = now;
        self.window_failure_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn cfg_with(sse_threshold: u32, window: Duration, transient_threshold: u32) -> AutoModeConfig {
        AutoModeConfig {
            sse_not_available_threshold: sse_threshold,
            connect_failure_window: window,
            connect_failure_threshold: transient_threshold,
        }
    }

    #[test]
    fn test_classify_sse_not_available() {
        let err = HealthError::SseNotAvailable("no EventService".to_string());
        assert_eq!(FailureKind::classify(&err), FailureKind::SseNotAvailable);
    }

    #[test]
    fn test_classify_other_errors_are_transient() {
        let err = HealthError::HttpError("500 Internal".to_string());
        assert_eq!(FailureKind::classify(&err), FailureKind::Transient);
        let err = HealthError::GenericError("tls handshake".to_string());
        assert_eq!(FailureKind::classify(&err), FailureKind::Transient);
    }

    #[test]
    fn test_sse_not_available_downgrades_at_threshold() {
        let now = Instant::now();
        let mut budget = AutoFailureBudget::new(cfg_with(2, Duration::from_secs(60), 10), now);

        assert_eq!(
            budget.record(FailureKind::SseNotAvailable, now),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::SseNotAvailable, now),
            BudgetDecision::Downgrade(DowngradeReason::SseNotAvailable)
        );
    }

    #[test]
    fn test_sse_not_available_default_threshold_is_one() {
        let now = Instant::now();
        let mut budget = AutoFailureBudget::new(AutoModeConfig::default(), now);

        assert_eq!(
            budget.record(FailureKind::SseNotAvailable, now),
            BudgetDecision::Downgrade(DowngradeReason::SseNotAvailable)
        );
    }

    #[test]
    fn test_transient_failures_accumulate_within_window() {
        let start = Instant::now();
        let mut budget = AutoFailureBudget::new(cfg_with(10, Duration::from_secs(60), 3), start);

        assert_eq!(
            budget.record(FailureKind::Transient, start),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(10)),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(20)),
            BudgetDecision::Downgrade(DowngradeReason::ConnectFailureBudgetExhausted)
        );
    }

    #[test]
    fn test_transient_window_resets_after_window() {
        let start = Instant::now();
        let mut budget = AutoFailureBudget::new(cfg_with(10, Duration::from_secs(60), 3), start);

        assert_eq!(
            budget.record(FailureKind::Transient, start),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(30)),
            BudgetDecision::Continue
        );

        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(70)),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(80)),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(90)),
            BudgetDecision::Downgrade(DowngradeReason::ConnectFailureBudgetExhausted)
        );
    }

    #[test]
    fn test_reset_transient_clears_window_counter() {
        let start = Instant::now();
        let mut budget = AutoFailureBudget::new(cfg_with(10, Duration::from_secs(60), 2), start);

        assert_eq!(
            budget.record(FailureKind::Transient, start),
            BudgetDecision::Continue
        );
        budget.reset_transient(start + Duration::from_secs(5));
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(6)),
            BudgetDecision::Continue
        );
        assert_eq!(
            budget.record(FailureKind::Transient, start + Duration::from_secs(7)),
            BudgetDecision::Downgrade(DowngradeReason::ConnectFailureBudgetExhausted)
        );
    }

    #[test]
    fn test_sse_not_available_counter_is_independent_of_transient_window() {
        let start = Instant::now();
        let mut budget = AutoFailureBudget::new(cfg_with(2, Duration::from_secs(60), 10), start);

        // reset_transient must not wipe sse_not_available count
        assert_eq!(
            budget.record(FailureKind::SseNotAvailable, start),
            BudgetDecision::Continue
        );
        budget.reset_transient(start + Duration::from_secs(1));
        assert_eq!(
            budget.record(FailureKind::SseNotAvailable, start + Duration::from_secs(2)),
            BudgetDecision::Downgrade(DowngradeReason::SseNotAvailable)
        );
    }
}
