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

// tests/exec_options_tests.rs
// Tests for ExecOptions and related functionality

use std::time::Duration;

use carbide_test_support::value_scenarios;
use libmlx::runner::exec_options::{ExecOptions, is_destructive_variable};

// Assert `options` holds the documented default configuration. `new()` is meant to
// be identical to `default()`, so both constructors are checked through here.
fn assert_default_options(options: &ExecOptions) {
    assert_eq!(options.timeout, Some(Duration::from_secs(30)));
    assert_eq!(options.retries, 3);
    assert_eq!(options.retry_delay, Duration::from_millis(500));
    assert_eq!(options.max_retry_delay, Duration::from_secs(60));
    assert_eq!(options.retry_multiplier, 2.0);
    assert!(!options.dry_run);
    assert!(!options.verbose);
    assert!(!options.log_json_output);
    assert!(!options.confirm_destructive);
}

#[test]
fn test_default_exec_options() {
    assert_default_options(&ExecOptions::default());
}

#[test]
fn test_new_exec_options() {
    // new() should be identical to default().
    assert_default_options(&ExecOptions::new());
}

#[test]
fn test_builder_pattern_timeout() {
    let options = ExecOptions::new().with_timeout(Some(Duration::from_secs(60)));

    assert_eq!(options.timeout, Some(Duration::from_secs(60)));

    // Test with None timeout
    let options_no_timeout = ExecOptions::new().with_timeout(None);

    assert_eq!(options_no_timeout.timeout, None);
}

#[test]
fn test_builder_pattern_retries() {
    let options = ExecOptions::new().with_retries(5);

    assert_eq!(options.retries, 5);
}

#[test]
fn test_builder_pattern_retry_delay() {
    let options = ExecOptions::new().with_retry_delay(Duration::from_secs(2));

    assert_eq!(options.retry_delay, Duration::from_secs(2));
}

#[test]
fn test_builder_pattern_max_retry_delay() {
    let options = ExecOptions::new().with_max_retry_delay(Duration::from_secs(120));

    assert_eq!(options.max_retry_delay, Duration::from_secs(120));
}

#[test]
fn test_builder_pattern_retry_multiplier() {
    let options = ExecOptions::new().with_retry_multiplier(1.5);

    assert_eq!(options.retry_multiplier, 1.5);

    // Test with aggressive multiplier
    let aggressive_options = ExecOptions::new().with_retry_multiplier(5.0);
    assert_eq!(aggressive_options.retry_multiplier, 5.0);

    // Test with conservative multiplier
    let conservative_options = ExecOptions::new().with_retry_multiplier(1.1);
    assert_eq!(conservative_options.retry_multiplier, 1.1);
}

// Each boolean setter round-trips the flag it sets and touches nothing else. The
// `set` closure applies the setter and `get` reads its field back, so one table
// covers every flag in both states.
#[test]
fn test_builder_pattern_boolean_flags() {
    struct BoolFlag {
        scenario: &'static str,
        value: bool,
        set: fn(ExecOptions, bool) -> ExecOptions,
        get: fn(&ExecOptions) -> bool,
    }

    let flags = [
        BoolFlag {
            scenario: "dry_run set true",
            value: true,
            set: |o, v| o.with_dry_run(v),
            get: |o| o.dry_run,
        },
        BoolFlag {
            scenario: "dry_run set false",
            value: false,
            set: |o, v| o.with_dry_run(v),
            get: |o| o.dry_run,
        },
        BoolFlag {
            scenario: "verbose set true",
            value: true,
            set: |o, v| o.with_verbose(v),
            get: |o| o.verbose,
        },
        BoolFlag {
            scenario: "verbose set false",
            value: false,
            set: |o, v| o.with_verbose(v),
            get: |o| o.verbose,
        },
        BoolFlag {
            scenario: "log_json_output set true",
            value: true,
            set: |o, v| o.with_log_json_output(v),
            get: |o| o.log_json_output,
        },
        BoolFlag {
            scenario: "log_json_output set false",
            value: false,
            set: |o, v| o.with_log_json_output(v),
            get: |o| o.log_json_output,
        },
        BoolFlag {
            scenario: "confirm_destructive set true",
            value: true,
            set: |o, v| o.with_confirm_destructive(v),
            get: |o| o.confirm_destructive,
        },
        BoolFlag {
            scenario: "confirm_destructive set false",
            value: false,
            set: |o, v| o.with_confirm_destructive(v),
            get: |o| o.confirm_destructive,
        },
    ];

    for flag in flags {
        let options = (flag.set)(ExecOptions::new(), flag.value);
        assert_eq!((flag.get)(&options), flag.value, "{}", flag.scenario);
    }
}

#[test]
fn test_builder_pattern_chaining() {
    let options = ExecOptions::new()
        .with_timeout(Some(Duration::from_secs(120)))
        .with_retries(5)
        .with_retry_delay(Duration::from_millis(100))
        .with_max_retry_delay(Duration::from_secs(30))
        .with_retry_multiplier(3.0)
        .with_dry_run(true)
        .with_verbose(true)
        .with_log_json_output(true)
        .with_confirm_destructive(true);

    assert_eq!(options.timeout, Some(Duration::from_secs(120)));
    assert_eq!(options.retries, 5);
    assert_eq!(options.retry_delay, Duration::from_millis(100));
    assert_eq!(options.max_retry_delay, Duration::from_secs(30));
    assert_eq!(options.retry_multiplier, 3.0);
    assert!(options.dry_run);
    assert!(options.verbose);
    assert!(options.log_json_output);
    assert!(options.confirm_destructive);
}

#[test]
fn test_exponential_backoff_configuration() {
    // Test exponential backoff parameters work together
    let backoff_options = ExecOptions::new()
        .with_retry_delay(Duration::from_millis(10))
        .with_max_retry_delay(Duration::from_millis(1000))
        .with_retry_multiplier(2.5)
        .with_retries(4);

    assert_eq!(backoff_options.retry_delay, Duration::from_millis(10));
    assert_eq!(backoff_options.max_retry_delay, Duration::from_millis(1000));
    assert_eq!(backoff_options.retry_multiplier, 2.5);
    assert_eq!(backoff_options.retries, 4);
}

#[test]
fn test_backoff_edge_cases() {
    // Test when max_retry_delay equals initial delay (no growth)
    let no_growth_options = ExecOptions::new()
        .with_retry_delay(Duration::from_millis(100))
        .with_max_retry_delay(Duration::from_millis(100));

    assert_eq!(
        no_growth_options.retry_delay,
        no_growth_options.max_retry_delay
    );

    // Test very small multiplier (minimal growth)
    let minimal_growth_options = ExecOptions::new().with_retry_multiplier(1.01);
    assert_eq!(minimal_growth_options.retry_multiplier, 1.01);

    // Test large multiplier (aggressive growth)
    let aggressive_growth_options = ExecOptions::new().with_retry_multiplier(10.0);
    assert_eq!(aggressive_growth_options.retry_multiplier, 10.0);
}

// Only the exact, case-sensitive name `OH_MY_DPU` is treated as destructive;
// everything else (other variables, the empty string, mismatched casing) is not.
#[test]
fn test_is_destructive_variable() {
    value_scenarios!(
        run = is_destructive_variable;
        "the predefined destructive variable" {
            "OH_MY_DPU" => true,
        }

        "SRIOV_EN is not destructive" {
            "SRIOV_EN" => false,
        }

        "NUM_OF_VFS is not destructive" {
            "NUM_OF_VFS" => false,
        }

        "POWER_MODE is not destructive" {
            "POWER_MODE" => false,
        }

        "the empty string is not destructive" {
            "" => false,
        }

        "lowercase does not match" {
            "oh_my_dpu" => false,
        }

        "mixed case does not match" {
            "Oh_My_Dpu" => false,
        }
    );
}

#[test]
fn test_exec_options_independence() {
    let options1 = ExecOptions::new().with_verbose(true);
    let options2 = ExecOptions::new().with_dry_run(true);

    // Ensure options are independent
    assert!(options1.verbose);
    assert!(!options1.dry_run);
    assert!(!options2.verbose);
    assert!(options2.dry_run);
}

#[test]
fn test_edge_case_values() {
    // Test extreme timeout values
    let options_zero = ExecOptions::new().with_timeout(Some(Duration::from_secs(0)));
    assert_eq!(options_zero.timeout, Some(Duration::from_secs(0)));

    let options_large = ExecOptions::new().with_timeout(Some(Duration::from_secs(u64::MAX)));
    assert_eq!(options_large.timeout, Some(Duration::from_secs(u64::MAX)));

    // Test maximum retries
    let options_max_retries = ExecOptions::new().with_retries(u32::MAX);
    assert_eq!(options_max_retries.retries, u32::MAX);

    // Test zero retry delay
    let options_zero_delay = ExecOptions::new().with_retry_delay(Duration::from_secs(0));
    assert_eq!(options_zero_delay.retry_delay, Duration::from_secs(0));

    // Test zero max retry delay
    let options_zero_max_delay = ExecOptions::new().with_max_retry_delay(Duration::from_secs(0));
    assert_eq!(
        options_zero_max_delay.max_retry_delay,
        Duration::from_secs(0)
    );

    // Test very large max retry delay
    let options_large_max_delay =
        ExecOptions::new().with_max_retry_delay(Duration::from_secs(u64::MAX));
    assert_eq!(
        options_large_max_delay.max_retry_delay,
        Duration::from_secs(u64::MAX)
    );
}

#[cfg(test)]
mod advanced_tests {
    use super::*;

    #[test]
    fn test_no_retry_config() {
        // Configuration with no retries.
        let no_retry_options = ExecOptions::new()
            .with_retries(0)
            .with_timeout(Some(Duration::from_secs(10)));

        assert_eq!(no_retry_options.retries, 0);
        assert_eq!(no_retry_options.timeout, Some(Duration::from_secs(10)));
    }
}
