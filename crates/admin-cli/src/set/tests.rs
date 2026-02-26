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

// The intent of the tests.rs file is to test the integrity of the
// command, including things like basic structure parsing, enum
// translations, and any external input validators that are
// configured. Specific "categories" are:
//
// Command Structure - Baseline debug_assert() of the entire command.
// Argument Parsing  - Ensure required/optional arg combinations parse correctly.

use clap::{CommandFactory, Parser};

use super::*;

// verify_cmd_structure runs a baseline clap debug_assert()
// to do basic command configuration checking and validation,
// ensuring things like unique argument definitions, group
// configurations, argument references, etc. Things that would
// otherwise be missed until runtime.
#[test]
fn verify_cmd_structure() {
    Cmd::command().debug_assert();
}

/////////////////////////////////////////////////////////////////////////////
// Argument Parsing
//
// This section contains tests specific to argument parsing,
// including testing required arguments, as well as optional
// flag-specific checking.

// parse_log_filter ensures log-filter parses with required filter arg.
#[test]
fn parse_log_filter() {
    let cmd = Cmd::try_parse_from(["set", "log-filter", "--filter", "debug"])
        .expect("should parse log-filter");

    match cmd {
        Cmd::LogFilter(args) => {
            assert_eq!(args.filter, "debug");
            assert_eq!(args.expiry, "1h"); // default
        }
        _ => panic!("expected LogFilter variant"),
    }
}

// parse_log_filter_with_expiry ensures log-filter parses
// with custom expiry.
#[test]
fn parse_log_filter_with_expiry() {
    let cmd = Cmd::try_parse_from([
        "set",
        "log-filter",
        "--filter",
        "trace",
        "--expiry",
        "30min",
    ])
    .expect("should parse log-filter with expiry");

    match cmd {
        Cmd::LogFilter(args) => {
            assert_eq!(args.filter, "trace");
            assert_eq!(args.expiry, "30min");
        }
        _ => panic!("expected LogFilter variant"),
    }
}

// parse_log_filter_missing_filter_fails ensures
// log-filter requires --filter.
#[test]
fn parse_log_filter_missing_filter_fails() {
    let result = Cmd::try_parse_from(["set", "log-filter"]);
    assert!(result.is_err(), "should fail without --filter");
}

// parse_create_machines ensures create-machines parses with --enabled.
#[test]
fn parse_create_machines() {
    let cmd = Cmd::try_parse_from(["set", "create-machines", "--enabled", "true"])
        .expect("should parse create-machines");

    match cmd {
        Cmd::CreateMachines(args) => {
            assert!(args.enabled);
        }
        _ => panic!("expected CreateMachines variant"),
    }
}

// parse_bmc_proxy ensures bmc-proxy parses with --enabled and --proxy.
#[test]
fn parse_bmc_proxy() {
    let cmd = Cmd::try_parse_from([
        "set",
        "bmc-proxy",
        "--enabled",
        "true",
        "--proxy",
        "proxy.example.com:8080",
    ])
    .expect("should parse bmc-proxy");

    match cmd {
        Cmd::BmcProxy(args) => {
            assert!(args.enabled);
            assert_eq!(args.proxy, Some("proxy.example.com:8080".to_string()));
        }
        _ => panic!("expected BmcProxy variant"),
    }
}

// parse_tracing_enabled_true ensures tracing-enabled parses true.
#[test]
fn parse_tracing_enabled_true() {
    let cmd =
        Cmd::try_parse_from(["set", "tracing-enabled", "true"]).expect("should parse tracing true");

    match cmd {
        Cmd::TracingEnabled(args) => {
            assert!(args.value);
        }
        _ => panic!("expected TracingEnabled variant"),
    }
}

// parse_tracing_enabled_false ensures tracing-enabled parses false.
#[test]
fn parse_tracing_enabled_false() {
    let cmd = Cmd::try_parse_from(["set", "tracing-enabled", "false"])
        .expect("should parse tracing false");

    match cmd {
        Cmd::TracingEnabled(args) => {
            assert!(!args.value);
        }
        _ => panic!("expected TracingEnabled variant"),
    }
}
