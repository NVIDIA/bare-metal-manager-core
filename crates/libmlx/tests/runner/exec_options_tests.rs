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

use carbide_test_support::{Check, check_values, value_scenarios};
use libmlx::runner::exec_options::{ExecOptions, is_destructive_variable};

#[derive(Debug, PartialEq)]
struct OptionsProjection {
    timeout: Option<Duration>,
    retries: u32,
    retry_delay: Duration,
    max_retry_delay: Duration,
    retry_multiplier: f32,
    dry_run: bool,
    verbose: bool,
    log_json_output: bool,
    confirm_destructive: bool,
}

impl From<ExecOptions> for OptionsProjection {
    fn from(options: ExecOptions) -> Self {
        Self {
            timeout: options.timeout,
            retries: options.retries,
            retry_delay: options.retry_delay,
            max_retry_delay: options.max_retry_delay,
            retry_multiplier: options.retry_multiplier,
            dry_run: options.dry_run,
            verbose: options.verbose,
            log_json_output: options.log_json_output,
            confirm_destructive: options.confirm_destructive,
        }
    }
}

fn default_projection() -> OptionsProjection {
    OptionsProjection {
        timeout: Some(Duration::from_secs(30)),
        retries: 3,
        retry_delay: Duration::from_millis(500),
        max_retry_delay: Duration::from_secs(60),
        retry_multiplier: 2.0,
        dry_run: false,
        verbose: false,
        log_json_output: false,
        confirm_destructive: false,
    }
}

#[derive(Clone, Copy)]
enum OptionsCase {
    Default,
    New,
    Timeout(Option<Duration>),
    Retries(u32),
    RetryDelay(Duration),
    MaxRetryDelay(Duration),
    RetryMultiplier(f32),
    DryRun(bool),
    Verbose(bool),
    LogJsonOutput(bool),
    ConfirmDestructive(bool),
}

fn build_options(case: OptionsCase) -> ExecOptions {
    match case {
        OptionsCase::Default => ExecOptions::default(),
        OptionsCase::New => ExecOptions::new(),
        OptionsCase::Timeout(timeout) => ExecOptions::new().with_timeout(timeout),
        OptionsCase::Retries(retries) => ExecOptions::new().with_retries(retries),
        OptionsCase::RetryDelay(delay) => ExecOptions::new().with_retry_delay(delay),
        OptionsCase::MaxRetryDelay(delay) => ExecOptions::new().with_max_retry_delay(delay),
        OptionsCase::RetryMultiplier(multiplier) => {
            ExecOptions::new().with_retry_multiplier(multiplier)
        }
        OptionsCase::DryRun(dry_run) => ExecOptions::new().with_dry_run(dry_run),
        OptionsCase::Verbose(verbose) => ExecOptions::new().with_verbose(verbose),
        OptionsCase::LogJsonOutput(log_json_output) => {
            ExecOptions::new().with_log_json_output(log_json_output)
        }
        OptionsCase::ConfirmDestructive(confirm_destructive) => {
            ExecOptions::new().with_confirm_destructive(confirm_destructive)
        }
    }
}

#[test]
fn exec_options_store_defaults_and_builder_values() {
    check_values(
        [
            Check {
                scenario: "Default uses the documented values",
                input: OptionsCase::Default,
                expect: default_projection(),
            },
            Check {
                scenario: "new uses the documented defaults",
                input: OptionsCase::New,
                expect: default_projection(),
            },
            Check {
                scenario: "timeout stores Some duration",
                input: OptionsCase::Timeout(Some(Duration::from_secs(60))),
                expect: OptionsProjection {
                    timeout: Some(Duration::from_secs(60)),
                    ..default_projection()
                },
            },
            Check {
                scenario: "timeout stores None",
                input: OptionsCase::Timeout(None),
                expect: OptionsProjection {
                    timeout: None,
                    ..default_projection()
                },
            },
            Check {
                scenario: "retries stores its value",
                input: OptionsCase::Retries(5),
                expect: OptionsProjection {
                    retries: 5,
                    ..default_projection()
                },
            },
            Check {
                scenario: "retry delay stores its duration",
                input: OptionsCase::RetryDelay(Duration::from_secs(2)),
                expect: OptionsProjection {
                    retry_delay: Duration::from_secs(2),
                    ..default_projection()
                },
            },
            Check {
                scenario: "maximum retry delay stores its duration",
                input: OptionsCase::MaxRetryDelay(Duration::from_secs(120)),
                expect: OptionsProjection {
                    max_retry_delay: Duration::from_secs(120),
                    ..default_projection()
                },
            },
            Check {
                scenario: "retry multiplier stores its value",
                input: OptionsCase::RetryMultiplier(1.5),
                expect: OptionsProjection {
                    retry_multiplier: 1.5,
                    ..default_projection()
                },
            },
            Check {
                scenario: "dry run stores true",
                input: OptionsCase::DryRun(true),
                expect: OptionsProjection {
                    dry_run: true,
                    ..default_projection()
                },
            },
            Check {
                scenario: "verbose stores true",
                input: OptionsCase::Verbose(true),
                expect: OptionsProjection {
                    verbose: true,
                    ..default_projection()
                },
            },
            Check {
                scenario: "JSON output logging stores true",
                input: OptionsCase::LogJsonOutput(true),
                expect: OptionsProjection {
                    log_json_output: true,
                    ..default_projection()
                },
            },
            Check {
                scenario: "destructive confirmation stores true",
                input: OptionsCase::ConfirmDestructive(true),
                expect: OptionsProjection {
                    confirm_destructive: true,
                    ..default_projection()
                },
            },
        ],
        |case| build_options(case).into(),
    );
}

#[test]
fn destructive_variable_names_are_exact_and_case_sensitive() {
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
