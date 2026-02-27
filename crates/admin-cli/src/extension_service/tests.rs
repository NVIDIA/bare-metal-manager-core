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
// ValueEnum Parsing - Test string parsing for types deriving claps ValueEnum.

use clap::{CommandFactory, Parser};

use super::common::ExtensionServiceType;
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

// parse_create ensures create parses with required
// arguments.
#[test]
fn parse_create() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "create",
        "--name",
        "my-service",
        "--type",
        "kubernetes-pod",
        "--data",
        "{}",
    ])
    .expect("should parse create");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.service_name, "my-service");
            assert_eq!(args.service_type, ExtensionServiceType::KubernetesPod);
            assert_eq!(args.data, "{}");
            assert!(args.service_id.is_none());
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_create_with_options ensures create parses with
// all options.
#[test]
fn parse_create_with_options() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "create",
        "--id",
        "svc-123",
        "--name",
        "my-service",
        "--type",
        "k8s",
        "--data",
        "{}",
        "--description",
        "My extension service",
        "--registry-url",
        "https://registry.example.com",
        "--username",
        "user",
        "--password",
        "pass",
    ])
    .expect("should parse create with options");

    match cmd {
        Cmd::Create(args) => {
            assert_eq!(args.service_id, Some("svc-123".to_string()));
            assert_eq!(args.description, Some("My extension service".to_string()));
            assert_eq!(
                args.registry_url,
                Some("https://registry.example.com".to_string())
            );
        }
        _ => panic!("expected Create variant"),
    }
}

// parse_update ensures update parses with required
// arguments.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "update",
        "--id",
        "svc-123",
        "--data",
        "{}",
    ])
    .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.service_id, "svc-123");
            assert_eq!(args.data, "{}");
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_delete ensures delete parses with
// service ID.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["extension-service", "delete", "--id", "svc-123"])
        .expect("should parse delete");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.service_id, "svc-123");
            assert!(args.versions.is_empty());
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_delete_with_versions ensures delete parses
// with version filter.
#[test]
fn parse_delete_with_versions() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "delete",
        "--id",
        "svc-123",
        "--versions",
        "v1,v2,v3",
    ])
    .expect("should parse delete with versions");

    match cmd {
        Cmd::Delete(args) => {
            assert_eq!(args.versions, vec!["v1", "v2", "v3"]);
        }
        _ => panic!("expected Delete variant"),
    }
}

// parse_show_no_args ensures show parses with no
// arguments (all services).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["extension-service", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.id.is_none());
            assert!(args.service_type.is_none());
            assert!(args.service_name.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_filters ensures show parses with
// filter options.
#[test]
fn parse_show_with_filters() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "show",
        "--id",
        "svc-123",
        "--type",
        "kubernetes-pod",
        "--name",
        "my-service",
    ])
    .expect("should parse show with filters");

    match cmd {
        Cmd::Show(args) => {
            assert_eq!(args.id, Some("svc-123".to_string()));
            assert_eq!(args.service_type, Some(ExtensionServiceType::KubernetesPod));
            assert_eq!(args.service_name, Some("my-service".to_string()));
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_get_version ensures get-version parses with
// service ID.
#[test]
fn parse_get_version() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "get-version",
        "--service-id",
        "svc-123",
    ])
    .expect("should parse get-version");

    match cmd {
        Cmd::GetVersion(args) => {
            assert_eq!(args.service_id, "svc-123");
            assert!(args.versions.is_empty());
        }
        _ => panic!("expected GetVersion variant"),
    }
}

// parse_show_instances ensures show-instances parses
// with service ID.
#[test]
fn parse_show_instances() {
    let cmd = Cmd::try_parse_from([
        "extension-service",
        "show-instances",
        "--service-id",
        "svc-123",
    ])
    .expect("should parse show-instances");

    match cmd {
        Cmd::ShowInstances(args) => {
            assert_eq!(args.service_id, "svc-123");
            assert!(args.version.is_none());
        }
        _ => panic!("expected ShowInstances variant"),
    }
}

// parse_create_missing_required_fails ensures create
// fails without required arguments.
#[test]
fn parse_create_missing_required_fails() {
    let result = Cmd::try_parse_from(["extension-service", "create"]);
    assert!(result.is_err(), "should fail without required arguments");
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// extension_service_type_value_enum ensures ExtensionServiceType
// parses from strings.
#[test]
fn extension_service_type_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        ExtensionServiceType::from_str("kubernetes-pod", false),
        Ok(ExtensionServiceType::KubernetesPod)
    ));
    // "k8s" is an alias for KubernetesPod
    assert!(matches!(
        ExtensionServiceType::from_str("k8s", false),
        Ok(ExtensionServiceType::KubernetesPod)
    ));
    assert!(ExtensionServiceType::from_str("invalid", false).is_err());
}
