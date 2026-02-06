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

use clap::{CommandFactory, Parser};

use super::args::*;
use super::cmds::{password_validator, url_validator};

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

// parse_add_ufm_with_required_args ensures add-ufm
// parses with only required args.
#[test]
fn parse_add_ufm_with_required_args() {
    let cmd = Cmd::try_parse_from(["credential", "add-ufm", "--url", "https://ufm.example.com"])
        .expect("should parse with required args");

    match cmd {
        Cmd::AddUFM(args) => {
            assert_eq!(args.url, "https://ufm.example.com");
            assert_eq!(args.token, ""); // default value
        }
        _ => panic!("expected AddUFM variant"),
    }
}

// parse_add_ufm_with_token ensures add-ufm parses with
// optional token.
#[test]
fn parse_add_ufm_with_token() {
    let cmd = Cmd::try_parse_from([
        "credential",
        "add-ufm",
        "--url",
        "https://ufm.example.com",
        "--token",
        "my-secret-token",
    ])
    .expect("should parse with token");

    match cmd {
        Cmd::AddUFM(args) => {
            assert_eq!(args.url, "https://ufm.example.com");
            assert_eq!(args.token, "my-secret-token");
        }
        _ => panic!("expected AddUFM variant"),
    }
}

// parse_add_ufm_missing_url_fails ensures add-ufm
// requires --url.
#[test]
fn parse_add_ufm_missing_url_fails() {
    let result = Cmd::try_parse_from(["credential", "add-ufm"]);
    assert!(result.is_err(), "should fail without required --url");
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

// parse_add_bmc_requires_kind_equals ensures add-bmc
// --kind requires = sign.
#[test]
fn parse_add_bmc_requires_kind_equals() {
    let result = Cmd::try_parse_from([
        "credential",
        "add-bmc",
        "--kind",
        "site-wide-root",
        "--password",
        "secret",
    ]);
    assert!(result.is_err(), "should fail without = in --kind=value");
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

// url_validator_accepts_valid_urls ensures valid URLs
// pass validation.
#[test]
fn url_validator_accepts_valid_urls() {
    assert!(url_validator("https://example.com".to_string()).is_ok());
    assert!(url_validator("http://localhost:8080".to_string()).is_ok());
    assert!(url_validator("https://ufm.corp.example.com/api".to_string()).is_ok());
}

// url_validator_rejects_invalid_urls ensures invalid
// URLs fail validation.
#[test]
fn url_validator_rejects_invalid_urls() {
    assert!(url_validator("not a url".to_string()).is_err());
    assert!(url_validator("".to_string()).is_err());
}

// password_validator_accepts_non_empty ensures non-empty
// passwords pass validation.
#[test]
fn password_validator_accepts_non_empty() {
    assert!(password_validator("secret123".to_string()).is_ok());
    assert!(password_validator("a".to_string()).is_ok());
    assert!(password_validator("spaces are ok".to_string()).is_ok());
}

// password_validator_rejects_empty ensures empty
// passwords fail validation.
#[test]
fn password_validator_rejects_empty() {
    assert!(password_validator("".to_string()).is_err());
}
