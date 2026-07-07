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
// Command Structure   - Baseline debug_assert() of the entire command.
// Argument Parsing    - Ensure required/optional arg combinations parse correctly.
// Validation Logic    - Test business logic validators on parsed arguments.

use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
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

// parse_show_no_args ensures show parses with no
// arguments (all machines).
#[test]
fn parse_show_no_args() {
    let cmd = Cmd::try_parse_from(["expected-machine", "show"]).expect("should parse show");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.bmc_mac_address.is_none());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_show_with_mac ensures show parses with MAC address.
#[test]
fn parse_show_with_mac() {
    let cmd = Cmd::try_parse_from(["expected-machine", "show", "1a:2b:3c:4d:5e:6f"])
        .expect("should parse show with MAC");

    match cmd {
        Cmd::Show(args) => {
            assert!(args.bmc_mac_address.is_some());
        }
        _ => panic!("expected Show variant"),
    }
}

// parse_add ensures add parses with required arguments.
#[test]
fn parse_add() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse add");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.bmc_username, "admin");
            assert_eq!(args.chassis_serial_number, "SN12345");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_without_password ensures add parses when --bmc-password is omitted.
#[test]
fn parse_add_without_password() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse add without password");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.bmc_password, None);
            assert_eq!(args.bmc_username, "admin");
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_add_with_options ensures add parses with
// all options.
#[test]
fn parse_add_with_options() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--meta-name",
        "MyMachine",
        "--label",
        "env:prod",
        "--sku-id",
        "sku123",
    ])
    .expect("should parse add with options");

    match cmd {
        Cmd::Add(args) => {
            assert_eq!(args.meta_name, Some("MyMachine".to_string()));
            assert_eq!(args.sku_id, Some("sku123".to_string()));
        }
        _ => panic!("expected Add variant"),
    }
}

// parse_delete ensures delete parses with MAC address.
#[test]
fn parse_delete() {
    let cmd = Cmd::try_parse_from(["expected-machine", "delete", "1a:2b:3c:4d:5e:6f"])
        .expect("should parse delete");

    assert!(matches!(cmd, Cmd::Delete(_)));
}

// parse_patch ensures patch parses with required arguments.
#[test]
fn parse_patch() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--sku-id",
        "new_sku",
    ])
    .expect("should parse patch");

    match cmd {
        Cmd::Patch(args) => {
            assert_eq!(args.sku_id, Some("new_sku".to_string()));
        }
        _ => panic!("expected Patch variant"),
    }
}

// parse_update ensures update parses with filename.
#[test]
fn parse_update() {
    let cmd = Cmd::try_parse_from(["expected-machine", "update", "--filename", "machine.json"])
        .expect("should parse update");

    match cmd {
        Cmd::Update(args) => {
            assert_eq!(args.filename, "machine.json");
        }
        _ => panic!("expected Update variant"),
    }
}

// parse_replace_all ensures replace-all parses with
// filename.
#[test]
fn parse_replace_all() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "replace-all",
        "--filename",
        "machines.json",
    ])
    .expect("should parse replace-all");

    match cmd {
        Cmd::ReplaceAll(args) => {
            assert_eq!(args.filename, "machines.json");
        }
        _ => panic!("expected ReplaceAll variant"),
    }
}

// parse_erase ensures erase parses with no arguments.
#[test]
fn parse_erase() {
    let cmd = Cmd::try_parse_from(["expected-machine", "erase"]).expect("should parse erase");

    assert!(matches!(cmd, Cmd::Erase(_)));
}

// Every malformed invocation is rejected at parse time -- a missing required
// argument, one half of a paired credential, or a flag left without its value.
#[test]
fn invalid_invocations_are_rejected() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|_| ())
                .map_err(drop)
        };
        "add without its required arguments" {
            &["expected-machine", "add"][..] => Fails,
        }

        "patch with a username but no password" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "admin",
            ][..] => Fails,
        }

        "patch with a password but no username" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-password",
                "secret",
            ][..] => Fails,
        }

        "update without --filename" {
            &["expected-machine", "update"][..] => Fails,
        }

        "add with --fallback-dpu-serial-number missing its value" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--fallback-dpu-serial-number",
            ][..] => Fails,
        }
    );
}

/////////////////////////////////////////////////////////////////////////////
// Validation Logic
//
// This section tests business logic validators on parsed arguments,
// including custom validation methods like duplicate detection.

// has_duplicate_dpu_serials flags a repeated `-d` serial on an otherwise valid
// add: unique serials and the no-serials case are clean, a repeat is caught.
#[test]
fn has_duplicate_dpu_serials_flags_repeats() {
    scenarios!(
        run = |argv| {
            add::Args::try_parse_from(argv.iter().copied())
                .map(|m| m.has_duplicate_dpu_serials())
                .map_err(drop)
        };
        "three unique serials" {
            &[
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--fallback-dpu-serial-number",
                "dpu1",
                "-d",
                "dpu2",
                "-d",
                "dpu3",
            ][..] => Yields(false),
        }

        "a repeated serial is detected" {
            &[
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "-d",
                "dpu1",
                "-d",
                "dpu2",
                "-d",
                "dpu3",
                "-d",
                "dpu1",
            ][..] => Yields(true),
        }

        "no serials at all" {
            &[
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
            ][..] => Yields(false),
        }
    );
}

// validate_patch_with_dpu_serials ensures patch validate()
// passes with unique DPU serials.
#[test]
fn validate_patch_with_dpu_serials() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--fallback-dpu-serial-number",
        "dpu1",
        "-d",
        "dpu2",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "unique serials should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_duplicate_dpu_serials_fails ensures patch
// validate() fails with duplicate DPU serials.
#[test]
fn validate_patch_duplicate_dpu_serials_fails() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--fallback-dpu-serial-number",
        "dpu1",
        "-d",
        "dpu2",
        "-d",
        "dpu3",
        "-d",
        "dpu2",
        "-d",
        "dpu4",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(
                args.validate().is_err(),
                "duplicate serials should fail validation"
            );
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_with_credentials ensures patch validate()
// passes with username and password together.
#[test]
fn validate_patch_with_credentials() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "credentials should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}

// validate_patch_all_fields ensures patch validate()
// passes with all fields provided.
#[test]
fn validate_patch_all_fields() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--fallback-dpu-serial-number",
        "dpu1",
    ])
    .expect("should parse");

    match cmd {
        Cmd::Patch(args) => {
            assert!(args.validate().is_ok(), "all fields should validate");
        }
        _ => panic!("expected Patch variant"),
    }
}

// parse_add_without_dpu_mode ensures the flag is optional and defaults to
// unset; downstream, unset is treated as "defer to the site-wide
// `[site_explorer] dpu_mode` setting" (which itself falls back to
// `DpuMode::DpuMode` when not set).
#[test]
fn parse_add_without_dpu_mode() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse without --dpu-mode");

    match cmd {
        Cmd::Add(args) => {
            assert!(args.dpu_mode.is_none(), "--dpu-mode should be optional");
        }
        _ => panic!("expected Add variant"),
    }
}

// `--dpu-mode <value>` parses to the matching DpuMode variant on both `add`
// (alongside the required credential/chassis args) and `patch` (where flipping
// dpu_mode on a single host is the whole point). The closure pulls dpu_mode off
// whichever variant parsed; each row pins the parsed `Some(variant)`.
#[test]
fn parse_dpu_mode_to_its_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => args.dpu_mode,
                    Cmd::Patch(args) => args.dpu_mode,
                    _ => panic!("expected Add or Patch variant"),
                })
                .map_err(drop)
        };
        "add --dpu-mode nic-mode" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--dpu-mode",
                "nic-mode",
            ][..] => Yields(Some(rpc::forge::DpuMode::NicMode)),
        }

        "add --dpu-mode no-dpu" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--dpu-mode",
                "no-dpu",
            ][..] => Yields(Some(rpc::forge::DpuMode::NoDpu)),
        }

        "add --dpu-mode dpu-mode" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--dpu-mode",
                "dpu-mode",
            ][..] => Yields(Some(rpc::forge::DpuMode::DpuMode)),
        }

        "patch --dpu-mode nic-mode" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--dpu-mode",
                "nic-mode",
            ][..] => Yields(Some(rpc::forge::DpuMode::NicMode)),
        }

        "patch --dpu-mode no-dpu" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--dpu-mode",
                "no-dpu",
            ][..] => Yields(Some(rpc::forge::DpuMode::NoDpu)),
        }

        "patch --dpu-mode dpu-mode" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--dpu-mode",
                "dpu-mode",
            ][..] => Yields(Some(rpc::forge::DpuMode::DpuMode)),
        }
    );
}

// parse_add_rejects_invalid_dpu_mode ensures clap rejects values that
// don't match the enum.
#[test]
fn parse_add_rejects_invalid_dpu_mode() {
    let result = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--dpu-mode",
        "garbage",
    ]);
    assert!(
        result.is_err(),
        "clap should reject --dpu-mode with an invalid value"
    );
}

// validate_patch_with_dpu_mode_only ensures `patch --dpu-mode nic-mode`
// alone (no other patchable fields) satisfies clap's ArgGroup and the
// `Args::validate()` "at least one field" check. The whole point of this
// patch is "flip dpu_mode", so it must work without dummy companion args.
#[test]
fn validate_patch_with_dpu_mode_only() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--dpu-mode",
        "nic-mode",
    ])
    .expect("patch --dpu-mode alone should parse (ArgGroup)");

    match cmd {
        Cmd::Patch(args) => {
            assert!(
                args.validate().is_ok(),
                "patch --dpu-mode alone should validate"
            );
        }
        _ => panic!("expected Patch variant"),
    }
}

// `--bmc-ip-allocation` is optional on `add`; unset is treated downstream as the
// server default (`auto`), which retains an auto-allocated BMC address.
#[test]
fn parse_add_without_bmc_ip_allocation() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
    ])
    .expect("should parse without --bmc-ip-allocation");

    match cmd {
        Cmd::Add(args) => {
            assert!(
                args.bmc_ip_allocation.is_none(),
                "--bmc-ip-allocation should be optional"
            );
        }
        _ => panic!("expected Add variant"),
    }
}

// `--bmc-ip-allocation <value>` parses to the matching BmcIpAllocationType variant
// on both `add` and `patch`. The closure pulls bmc_ip_allocation off whichever
// variant parsed; each row pins the parsed `Some(variant)`.
#[test]
fn parse_bmc_ip_allocation_to_its_variant() {
    scenarios!(
        run = |argv| {
            Cmd::try_parse_from(argv.iter().copied())
                .map(|cmd| match cmd {
                    Cmd::Add(args) => args.bmc_ip_allocation,
                    Cmd::Patch(args) => args.bmc_ip_allocation,
                    _ => panic!("expected Add or Patch variant"),
                })
                .map_err(drop)
        };
        "add --bmc-ip-allocation retained" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--bmc-ip-allocation",
                "retained",
            ][..] => Yields(Some(rpc::forge::BmcIpAllocationType::Retained)),
        }

        "add --bmc-ip-allocation dynamic" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--bmc-ip-allocation",
                "dynamic",
            ][..] => Yields(Some(rpc::forge::BmcIpAllocationType::Dynamic)),
        }

        "add --bmc-ip-allocation auto" {
            &[
                "expected-machine",
                "add",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-username",
                "admin",
                "--bmc-password",
                "secret",
                "--chassis-serial-number",
                "SN12345",
                "--bmc-ip-allocation",
                "auto",
            ][..] => Yields(Some(rpc::forge::BmcIpAllocationType::Auto)),
        }

        "patch --bmc-ip-allocation retained" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-ip-allocation",
                "retained",
            ][..] => Yields(Some(rpc::forge::BmcIpAllocationType::Retained)),
        }

        "patch --bmc-ip-allocation fixed" {
            &[
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "1a:2b:3c:4d:5e:6f",
                "--bmc-ip-allocation",
                "fixed",
            ][..] => Yields(Some(rpc::forge::BmcIpAllocationType::Fixed)),
        }
    );
}

// clap rejects `--bmc-ip-allocation` values that don't match the enum.
#[test]
fn parse_add_rejects_invalid_bmc_ip_allocation() {
    let result = Cmd::try_parse_from([
        "expected-machine",
        "add",
        "--bmc-mac-address",
        "1a:2b:3c:4d:5e:6f",
        "--bmc-username",
        "admin",
        "--bmc-password",
        "secret",
        "--chassis-serial-number",
        "SN12345",
        "--bmc-ip-allocation",
        "garbage",
    ]);
    assert!(
        result.is_err(),
        "clap should reject --bmc-ip-allocation with an invalid value"
    );
}

// `patch --bmc-ip-allocation retained` alone (no other patchable fields) must
// satisfy clap's ArgGroup and `Args::validate()`'s "at least one field" check.
// A patch that sets only this field.
#[test]
fn validate_patch_with_bmc_ip_allocation_only() {
    let cmd = Cmd::try_parse_from([
        "expected-machine",
        "patch",
        "--bmc-mac-address",
        "00:00:00:00:00:00",
        "--bmc-ip-allocation",
        "retained",
    ])
    .expect("patch --bmc-ip-allocation alone should parse (ArgGroup)");

    match cmd {
        Cmd::Patch(args) => {
            assert!(
                args.validate().is_ok(),
                "patch --bmc-ip-allocation alone should validate"
            );
        }
        _ => panic!("expected Patch variant"),
    }
}
