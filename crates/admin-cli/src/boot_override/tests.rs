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

// parse_get ensures get subcommand parses interface_id.
#[test]
fn parse_get() {
    let cmd = Cmd::try_parse_from([
        "boot-override",
        "get",
        "550e8400-e29b-41d4-a716-446655440000",
    ])
    .expect("should parse get");

    match cmd {
        Cmd::Get(args) => {
            assert_eq!(
                args.inner.interface_id.to_string(),
                "550e8400-e29b-41d4-a716-446655440000"
            );
        }
        _ => panic!("expected Get variant"),
    }
}

// parse_clear ensures clear subcommand parses interface_id.
#[test]
fn parse_clear() {
    let cmd = Cmd::try_parse_from([
        "boot-override",
        "clear",
        "550e8400-e29b-41d4-a716-446655440000",
    ])
    .expect("should parse clear");

    match cmd {
        Cmd::Clear(args) => {
            assert_eq!(
                args.inner.interface_id.to_string(),
                "550e8400-e29b-41d4-a716-446655440000"
            );
        }
        _ => panic!("expected Clear variant"),
    }
}

// parse_set_basic ensures set subcommand parses with
// just interface_id.
#[test]
fn parse_set_basic() {
    let cmd = Cmd::try_parse_from([
        "boot-override",
        "set",
        "550e8400-e29b-41d4-a716-446655440000",
    ])
    .expect("should parse set");

    match cmd {
        Cmd::Set(args) => {
            assert_eq!(
                args.interface_id.to_string(),
                "550e8400-e29b-41d4-a716-446655440000"
            );
            assert!(args.custom_pxe.is_none());
            assert!(args.custom_user_data.is_none());
        }
        _ => panic!("expected Set variant"),
    }
}

// parse_set_with_options ensures set subcommand parses
// with custom_pxe and custom_user_data.
#[test]
fn parse_set_with_options() {
    let cmd = Cmd::try_parse_from([
        "boot-override",
        "set",
        "550e8400-e29b-41d4-a716-446655440000",
        "--custom-pxe",
        "http://pxe.example.com/boot",
        "--custom-user-data",
        "some-user-data",
    ])
    .expect("should parse set with options");

    match cmd {
        Cmd::Set(args) => {
            assert_eq!(
                args.custom_pxe,
                Some("http://pxe.example.com/boot".to_string())
            );
            assert_eq!(args.custom_user_data, Some("some-user-data".to_string()));
        }
        _ => panic!("expected Set variant"),
    }
}

// parse_set_short_options ensures set subcommand parses
// short flags -p and -u.
#[test]
fn parse_set_short_options() {
    let cmd = Cmd::try_parse_from([
        "boot-override",
        "set",
        "550e8400-e29b-41d4-a716-446655440000",
        "-p",
        "http://pxe.example.com/boot",
        "-u",
        "some-user-data",
    ])
    .expect("should parse set with short options");

    match cmd {
        Cmd::Set(args) => {
            assert_eq!(
                args.custom_pxe,
                Some("http://pxe.example.com/boot".to_string())
            );
            assert_eq!(args.custom_user_data, Some("some-user-data".to_string()));
        }
        _ => panic!("expected Set variant"),
    }
}

// parse_requires_interface_id ensures subcommands
// require interface_id.
#[test]
fn parse_requires_interface_id() {
    let result = Cmd::try_parse_from(["boot-override", "get"]);
    assert!(result.is_err(), "should fail without interface_id");
}
