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

use mlxconfig_runner::ExecOptions;
use mlxconfig_runner::exec_options::is_destructive_variable;

#[test]
fn test_default_exec_options() {
    let options = ExecOptions::default();

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
fn test_new_exec_options() {
    let options = ExecOptions::new();

    // Should be identical to default
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

#[test]
fn test_builder_pattern_dry_run() {
    let options = ExecOptions::new().with_dry_run(true);

    assert!(options.dry_run);

    let options_false = ExecOptions::new().with_dry_run(false);

    assert!(!options_false.dry_run);
}

#[test]
fn test_builder_pattern_verbose() {
    let options = ExecOptions::new().with_verbose(true);

    assert!(options.verbose);

    let options_false = ExecOptions::new().with_verbose(false);

    assert!(!options_false.verbose);
}

#[test]
fn test_builder_pattern_log_json_output() {
    let options = ExecOptions::new().with_log_json_output(true);

    assert!(options.log_json_output);

    let options_false = ExecOptions::new().with_log_json_output(false);

    assert!(!options_false.log_json_output);
}

#[test]
fn test_builder_pattern_confirm_destructive() {
    let options = ExecOptions::new().with_confirm_destructive(true);

    assert!(options.confirm_destructive);

    let options_false = ExecOptions::new().with_confirm_destructive(false);

    assert!(!options_false.confirm_destructive);
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

#[test]
fn test_is_destructive_variable() {
    // Test the predefined destructive variable
    assert!(is_destructive_variable("OH_MY_DPU"));

    // Test non-destructive variables
    assert!(!is_destructive_variable("SRIOV_EN"));
    assert!(!is_destructive_variable("NUM_OF_VFS"));
    assert!(!is_destructive_variable("POWER_MODE"));
    assert!(!is_destructive_variable(""));

    // Test case sensitivity
    assert!(!is_destructive_variable("oh_my_dpu"));
    assert!(!is_destructive_variable("Oh_My_Dpu"));
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
    fn test_sample1_config() {
        let sample1_options = ExecOptions::new()
            .with_timeout(Some(Duration::from_secs(45)))
            .with_retries(2)
            .with_retry_delay(Duration::from_secs(3))
            .with_max_retry_delay(Duration::from_secs(30))
            .with_retry_multiplier(2.0)
            .with_verbose(false)
            .with_confirm_destructive(true);

        assert_eq!(sample1_options.timeout, Some(Duration::from_secs(45)));
        assert_eq!(sample1_options.retries, 2);
        assert_eq!(sample1_options.retry_delay, Duration::from_secs(3));
        assert_eq!(sample1_options.max_retry_delay, Duration::from_secs(30));
        assert_eq!(sample1_options.retry_multiplier, 2.0);
        assert!(!sample1_options.verbose);
        assert!(sample1_options.confirm_destructive);
        assert!(!sample1_options.dry_run);
        assert!(!sample1_options.log_json_output);
    }

    #[test]
    fn test_sample2_config() {
        let sample2_options = ExecOptions::new()
            .with_dry_run(true)
            .with_verbose(true)
            .with_log_json_output(true)
            .with_retries(0)
            .with_retry_delay(Duration::from_millis(10)) // Fast for testing
            .with_confirm_destructive(false);

        assert!(sample2_options.dry_run);
        assert!(sample2_options.verbose);
        assert!(sample2_options.log_json_output);
        assert_eq!(sample2_options.retries, 0);
        assert_eq!(sample2_options.retry_delay, Duration::from_millis(10));
        assert!(!sample2_options.confirm_destructive);
    }

    #[test]
    fn test_sample3_config() {
        let sample3_options = ExecOptions::new()
            .with_timeout(Some(Duration::from_secs(90)))
            .with_retries(5)
            .with_retry_delay(Duration::from_millis(200))
            .with_max_retry_delay(Duration::from_secs(10))
            .with_retry_multiplier(1.5) // Conservative growth
            .with_verbose(true);

        assert_eq!(sample3_options.timeout, Some(Duration::from_secs(90)));
        assert_eq!(sample3_options.retries, 5);
        assert_eq!(sample3_options.retry_delay, Duration::from_millis(200));
        assert_eq!(sample3_options.max_retry_delay, Duration::from_secs(10));
        assert_eq!(sample3_options.retry_multiplier, 1.5);
        assert!(sample3_options.verbose);
    }

    #[test]
    fn test_sample4_config() {
        // Configuration with aggressive exponential backoff
        let sample4_options = ExecOptions::new()
            .with_retries(3)
            .with_retry_delay(Duration::from_millis(50))
            .with_max_retry_delay(Duration::from_millis(500))
            .with_retry_multiplier(4.0); // Aggressive growth

        assert_eq!(sample4_options.retries, 3);
        assert_eq!(sample4_options.retry_delay, Duration::from_millis(50));
        assert_eq!(sample4_options.max_retry_delay, Duration::from_millis(500));
        assert_eq!(sample4_options.retry_multiplier, 4.0);
    }

    #[test]
    fn test_sample5_config() {
        // Configuration with conservative exponential backoff
        let sample5_options = ExecOptions::new()
            .with_retries(10)
            .with_retry_delay(Duration::from_millis(100))
            .with_max_retry_delay(Duration::from_secs(30))
            .with_retry_multiplier(1.2); // Very slow growth

        assert_eq!(sample5_options.retries, 10);
        assert_eq!(sample5_options.retry_delay, Duration::from_millis(100));
        assert_eq!(sample5_options.max_retry_delay, Duration::from_secs(30));
        assert_eq!(sample5_options.retry_multiplier, 1.2);
    }

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
