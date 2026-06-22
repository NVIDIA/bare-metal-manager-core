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
// Enum Conversions  - Test From implementations for proto <-> non-proto mapping.
// ValueEnum Parsing - Test string parsing for types deriving claps ValueEnum.
// Custom Validators - Test external input validation functions.

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
use clap::{CommandFactory, Parser};

use super::common::{BmcCredentialType, UefiCredentialType, password_validator, url_validator};
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

// add-ufm routes to the AddUFM variant and carries its url plus token, where the
// token defaults to the empty string when its optional flag is omitted.
#[test]
fn parse_add_ufm_fields() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::AddUFM(args) => (args.url, args.token),
                    _ => panic!("expected AddUFM variant"),
                })
                .map_err(drop)
        };
        "required args only -- token defaults to empty" {
            &["credential", "add-ufm", "--url", "https://ufm.example.com"][..] => Yields(("https://ufm.example.com".to_string(), String::new())),
        }

        "with optional --token" {
            &[
                "credential",
                "add-ufm",
                "--url",
                "https://ufm.example.com",
                "--token",
                "my-secret-token",
            ][..] => Yields((
                "https://ufm.example.com".to_string(),
                "my-secret-token".to_string(),
            )),
        }
    );
}

// parse_add_bmc_with_all_args ensures add-bmc parses
// with all arguments.
#[test]
fn parse_add_bmc_with_all_args() {
    let cmd = Cmd::try_parse_from([
        "credential",
        "add-bmc",
        "--kind=site-wide-root",
        "--password",
        "secret123",
        "--username",
        "admin",
        "--mac-address",
        "00:11:22:33:44:55",
    ])
    .expect("should parse add-bmc");

    match cmd {
        Cmd::AddBMC(args) => {
            assert!(matches!(args.kind, BmcCredentialType::SiteWideRoot));
            assert_eq!(args.password, "secret123");
            assert_eq!(args.username, Some("admin".to_string()));
            assert!(args.mac_address.is_some());
        }
        _ => panic!("expected AddBMC variant"),
    }
}

// parse_add_uefi ensures add-uefi parses correctly.
#[test]
fn parse_add_uefi() {
    let cmd = Cmd::try_parse_from([
        "credential",
        "add-uefi",
        "--kind=dpu",
        "--password=uefi-password",
    ])
    .expect("should parse add-uefi");

    match cmd {
        Cmd::AddUefi(args) => {
            assert!(matches!(args.kind, UefiCredentialType::Dpu));
            assert_eq!(args.password, "uefi-password");
        }
        _ => panic!("expected AddUefi variant"),
    }
}

// parse_add_nic_lockdown_ikm ensures add-nic-lockdown-ikm parses with the
// required password.
#[test]
fn parse_add_nic_lockdown_ikm() {
    let cmd = Cmd::try_parse_from([
        "credential",
        "add-nic-lockdown-ikm",
        "--password",
        "ikm-secret",
    ])
    .expect("should parse add-nic-lockdown-ikm");

    match cmd {
        Cmd::AddNicLockdownIkm(args) => {
            assert_eq!(args.password, "ikm-secret");
        }
        _ => panic!("expected AddNicLockdownIkm variant"),
    }
}

// Every malformed invocation is rejected at parse time -- a subcommand missing
// its required flag, or a --kind value passed without the required `=` separator.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "add-ufm without required --url" {
            &["credential", "add-ufm"][..] => Fails,
        }

        "add-bmc --kind without the = separator" {
            &[
                "credential",
                "add-bmc",
                "--kind",
                "site-wide-root",
                "--password",
                "secret",
            ][..] => Fails,
        }

        "add-nic-lockdown-ikm without required --password" {
            &["credential", "add-nic-lockdown-ikm"][..] => Fails,
        }
    );
}

// add_nic_lockdown_ikm_maps_to_proto ensures the parsed args convert into a
// CredentialCreationRequest carrying the SiteWideNicLockdownIkm type.
#[test]
fn add_nic_lockdown_ikm_maps_to_proto() {
    use rpc::forge::{self as forgerpc, CredentialType};

    let args = add_nic_lockdown_ikm::Args {
        password: "ikm-secret".to_string(),
    };
    let req = forgerpc::CredentialCreationRequest::try_from(args).expect("convert");
    assert_eq!(
        req.credential_type,
        CredentialType::SiteWideNicLockdownIkm as i32
    );
    assert_eq!(req.password, "ikm-secret");
    assert!(req.username.is_none());
    assert!(req.mac_address.is_none());
}

/////////////////////////////////////////////////////////////////////////////
// Enum Conversions
//
// This section is for testing the proto <-> non-proto enum
// From implementations that exist, ensuring enums translate
// from -> into their expected variants.

// bmc_credential_type_to_proto ensures BmcCredentialType
// converts to protobuf CredentialType.
#[test]
fn bmc_credential_type_to_proto() {
    use rpc::forge::CredentialType;

    assert!(matches!(
        CredentialType::from(BmcCredentialType::SiteWideRoot),
        CredentialType::SiteWideBmcRoot
    ));
    assert!(matches!(
        CredentialType::from(BmcCredentialType::BmcRoot),
        CredentialType::RootBmcByMacAddress
    ));
    assert!(matches!(
        CredentialType::from(BmcCredentialType::BmcForgeAdmin),
        CredentialType::BmcForgeAdminByMacAddress
    ));
}

// uefi_credential_type_to_proto ensures
// UefiCredentialType converts to protobuf CredentialType.
#[test]
fn uefi_credential_type_to_proto() {
    use rpc::forge::CredentialType;

    assert!(matches!(
        CredentialType::from(UefiCredentialType::Dpu),
        CredentialType::DpuUefi
    ));
    assert!(matches!(
        CredentialType::from(UefiCredentialType::Host),
        CredentialType::HostUefi
    ));
}

/////////////////////////////////////////////////////////////////////////////
// ValueEnum Parsing
//
// These tests are for testing argument values which derive
// ValueEnum, ensuring the string representations of said
// values correctly convert back into their expected variant,
// or fail otherwise.

// bmc_credential_type_value_enum ensures
// BmcCredentialType parses from kebab-case strings.
#[test]
fn bmc_credential_type_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        BmcCredentialType::from_str("site-wide-root", false),
        Ok(BmcCredentialType::SiteWideRoot)
    ));
    assert!(matches!(
        BmcCredentialType::from_str("bmc-root", false),
        Ok(BmcCredentialType::BmcRoot)
    ));
    assert!(matches!(
        BmcCredentialType::from_str("bmc-forge-admin", false),
        Ok(BmcCredentialType::BmcForgeAdmin)
    ));
    assert!(BmcCredentialType::from_str("invalid", false).is_err());
}

// uefi_credential_type_value_enum ensures UefiCredentialType
// parses from strings.
#[test]
fn uefi_credential_type_value_enum() {
    use clap::ValueEnum;

    assert!(matches!(
        UefiCredentialType::from_str("dpu", false),
        Ok(UefiCredentialType::Dpu)
    ));
    assert!(matches!(
        UefiCredentialType::from_str("host", false),
        Ok(UefiCredentialType::Host)
    ));
    assert!(UefiCredentialType::from_str("invalid", false).is_err());
}

/////////////////////////////////////////////////////////////////////////////
// Validators
//
// This section contains tests for testing argument values
// which are processed by custom/external validation
// functions. Here, we test that the functions work as expected.

// url_validator accepts well-formed http(s) URLs and rejects anything that does
// not parse as a URL (including the empty string).
#[test]
fn url_validator_accepts_only_valid_urls() {
    scenarios!(
        run = |url| url_validator(url.to_string()).map(|_| ()).map_err(drop);
        "https host" {
            "https://example.com" => Yields(()),
        }

        "http host with port" {
            "http://localhost:8080" => Yields(()),
        }

        "https host with path" {
            "https://ufm.corp.example.com/api" => Yields(()),
        }

        "not a url" {
            "not a url" => Fails,
        }

        "empty string" {
            "" => Fails,
        }
    );
}

// password_validator accepts any non-empty password and rejects only the empty
// string.
#[test]
fn password_validator_accepts_only_non_empty() {
    scenarios!(
        run = |pw| password_validator(pw.to_string()).map(|_| ()).map_err(drop);
        "ordinary password" {
            "secret123" => Yields(()),
        }

        "single character" {
            "a" => Yields(()),
        }

        "spaces are allowed" {
            "spaces are ok" => Yields(()),
        }

        "empty string is rejected" {
            "" => Fails,
        }
    );
}
