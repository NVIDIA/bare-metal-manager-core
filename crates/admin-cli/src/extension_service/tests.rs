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

use carbide_test_support::Outcome::*;
use carbide_test_support::{Case, check_cases, scenarios};
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

// Create parses both with just the required arguments and with the full
// option set; each row asserts the fields the original test inspected:
// (service_id, service_name, service_type, data, description, registry_url).
#[test]
fn parse_create_routes_and_binds_fields() {
    type CreateFields = (
        Option<String>,
        String,
        ExtensionServiceType,
        String,
        Option<String>,
        Option<String>,
    );

    check_cases(
        [
            Case {
                scenario: "create with required arguments",
                input: &[
                    "extension-service",
                    "create",
                    "--name",
                    "my-service",
                    "--type",
                    "kubernetes-pod",
                    "--data",
                    "{}",
                ][..],
                expect: Yields((
                    None,
                    "my-service".to_string(),
                    ExtensionServiceType::KubernetesPod,
                    "{}".to_string(),
                    None,
                    None,
                )),
            },
            Case {
                scenario: "create with all options",
                input: &[
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
                ][..],
                expect: Yields((
                    Some("svc-123".to_string()),
                    "my-service".to_string(),
                    ExtensionServiceType::KubernetesPod,
                    "{}".to_string(),
                    Some("My extension service".to_string()),
                    Some("https://registry.example.com".to_string()),
                )),
            },
        ],
        |argv| -> Result<CreateFields, ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::Create(args) => Ok((
                    args.service_id,
                    args.service_name,
                    args.service_type,
                    args.data,
                    args.description,
                    args.registry_url,
                )),
                _ => panic!("expected Create variant"),
            }
        },
    );
}

// Update routes to the Update variant and binds (service_id, data).
#[test]
fn parse_update_routes_and_binds_fields() {
    check_cases(
        [Case {
            scenario: "update with required arguments",
            input: &[
                "extension-service",
                "update",
                "--id",
                "svc-123",
                "--data",
                "{}",
            ][..],
            expect: Yields(("svc-123".to_string(), "{}".to_string())),
        }],
        |argv| -> Result<(String, String), ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::Update(args) => Ok((args.service_id, args.data)),
                _ => panic!("expected Update variant"),
            }
        },
    );
}

// Delete routes to the Delete variant, with an optional version filter; each
// row asserts (service_id, versions).
#[test]
fn parse_delete_routes_and_binds_fields() {
    check_cases(
        [
            Case {
                scenario: "delete with service ID only",
                input: &["extension-service", "delete", "--id", "svc-123"][..],
                expect: Yields(("svc-123".to_string(), Vec::<String>::new())),
            },
            Case {
                scenario: "delete with version filter",
                input: &[
                    "extension-service",
                    "delete",
                    "--id",
                    "svc-123",
                    "--versions",
                    "v1,v2,v3",
                ][..],
                expect: Yields((
                    "svc-123".to_string(),
                    vec!["v1".to_string(), "v2".to_string(), "v3".to_string()],
                )),
            },
        ],
        |argv| -> Result<(String, Vec<String>), ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::Delete(args) => Ok((args.service_id, args.versions)),
                _ => panic!("expected Delete variant"),
            }
        },
    );
}

// Show routes to the Show variant with all filters optional; each row asserts
// (id, service_type, service_name).
#[test]
fn parse_show_routes_and_binds_fields() {
    type ShowFields = (Option<String>, Option<ExtensionServiceType>, Option<String>);

    check_cases(
        [
            Case {
                scenario: "show with no arguments",
                input: &["extension-service", "show"][..],
                expect: Yields((None, None, None)),
            },
            Case {
                scenario: "show with filter options",
                input: &[
                    "extension-service",
                    "show",
                    "--id",
                    "svc-123",
                    "--type",
                    "kubernetes-pod",
                    "--name",
                    "my-service",
                ][..],
                expect: Yields((
                    Some("svc-123".to_string()),
                    Some(ExtensionServiceType::KubernetesPod),
                    Some("my-service".to_string()),
                )),
            },
        ],
        |argv| -> Result<ShowFields, ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::Show(args) => Ok((args.id, args.service_type, args.service_name)),
                _ => panic!("expected Show variant"),
            }
        },
    );
}

// GetVersion routes to the GetVersion variant and binds (service_id, versions).
#[test]
fn parse_get_version_routes_and_binds_fields() {
    check_cases(
        [Case {
            scenario: "get-version with service ID",
            input: &[
                "extension-service",
                "get-version",
                "--service-id",
                "svc-123",
            ][..],
            expect: Yields(("svc-123".to_string(), Vec::<String>::new())),
        }],
        |argv| -> Result<(String, Vec<String>), ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::GetVersion(args) => Ok((args.service_id, args.versions)),
                _ => panic!("expected GetVersion variant"),
            }
        },
    );
}

// ShowInstances routes to the ShowInstances variant and binds
// (service_id, version).
#[test]
fn parse_show_instances_routes_and_binds_fields() {
    check_cases(
        [Case {
            scenario: "show-instances with service ID",
            input: &[
                "extension-service",
                "show-instances",
                "--service-id",
                "svc-123",
            ][..],
            expect: Yields(("svc-123".to_string(), None)),
        }],
        |argv| -> Result<(String, Option<String>), ()> {
            match Cmd::try_parse_from(argv.iter().copied()).map_err(drop)? {
                Cmd::ShowInstances(args) => Ok((args.service_id, args.version)),
                _ => panic!("expected ShowInstances variant"),
            }
        },
    );
}

// Every malformed invocation is rejected at parse time.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "create without its required arguments" {
            &["extension-service", "create"][..] => Fails,
        }
    );
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// extension_service_type_value_enum ensures ExtensionServiceType
// parses from strings ("k8s" is an alias for KubernetesPod, and an
// unknown value is rejected).
#[test]
fn extension_service_type_value_enum() {
    use clap::ValueEnum;

    scenarios!(
        run = |s| ExtensionServiceType::from_str(s, false).map_err(drop);
        "canonical kubernetes-pod" {
            "kubernetes-pod" => Yields(ExtensionServiceType::KubernetesPod),
        }

        "k8s alias maps to KubernetesPod" {
            "k8s" => Yields(ExtensionServiceType::KubernetesPod),
        }

        "unknown value is rejected" {
            "invalid" => Fails,
        }
    );
}
