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

// parse_show ensures show parses with no arguments.
#[test]
fn parse_show() {
    let cmd = Cmd::try_parse_from(["tpm-ca", "show"]).expect("should parse show");

    assert!(matches!(cmd, Cmd::Show(_)));
}

// parse_delete ensures delete parses with ca_id.
#[test]
fn parse_delete() {
    let cmd =
        Cmd::try_parse_from(["tpm-ca", "delete", "--ca-id", "123"]).expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.ca_id, 123);
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_add ensures add parses with filename.
#[test]
fn parse_add() {
    let cmd =
        Cmd::try_parse_from(["tpm-ca", "add", "--filename", "ca.pem"]).expect("should parse add");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.filename, "ca.pem");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_show_unmatched_ek ensures show-unmatched-ek parses.
#[test]
fn parse_show_unmatched_ek() {
    let cmd = Cmd::try_parse_from(["tpm-ca", "show-unmatched-ek"])
        .expect("should parse show-unmatched-ek");

    assert!(matches!(cmd, Cmd::ShowUnmatchedEk(_)));
}

// parse_add_bulk ensures add-bulk parses with dirname.
#[test]
fn parse_add_bulk() {
    let cmd = Cmd::try_parse_from(["tpm-ca", "add-bulk", "--dirname", "/path/to/certs"])
        .expect("should parse add-bulk");

    match cmd {
        Cmd::AddBulk(args) => {
            assert_eq!(args.dirname, "/path/to/certs");
        }
        _ => panic!("expected AddBulk variant"),
    }
}

// parse_delete_missing_ca_id_fails ensures delete fails
// without --ca-id.
#[test]
fn parse_delete_missing_ca_id_fails() {
    let result = Cmd::try_parse_from(["tpm-ca", "delete"]);
    assert!(result.is_err(), "should fail without --ca-id");
}

// parse_add_missing_filename_fails ensures add fails
// without --filename.
#[test]
fn parse_add_missing_filename_fails() {
    let result = Cmd::try_parse_from(["tpm-ca", "add"]);
    assert!(result.is_err(), "should fail without --filename");
}

// parse_add_bulk_missing_dirname_fails ensures add-bulk
// fails without --dirname.
#[test]
fn parse_add_bulk_missing_dirname_fails() {
    let result = Cmd::try_parse_from(["tpm-ca", "add-bulk"]);
    assert!(result.is_err(), "should fail without --dirname");
}
