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

use clap::Parser;
use libmlx::lockdown::cmd::args::{Cli, Commands, LockdownAction, OutputFormat};
use libmlx::lockdown::cmd::cmds::run_cli;

#[test]
fn test_cli_parsing() {
    // Test parsing various command line arguments
    let cli = Cli::try_parse_from(["mlxconfig-lockdown", "lockdown", "status", "04:00.0"]).unwrap();

    // Just ensure it parsed without errors
    assert!(matches!(cli.command, Commands::Lockdown { .. }));
}

#[test]
fn test_cli_help() {
    // Test that help works without panicking
    let result = Cli::try_parse_from(["mlxconfig-lockdown", "--help"]);
    assert!(result.is_err()); // Help exits with error code, but that's expected
}

#[test]
fn test_lockdown_subcommands() {
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "lock",
        "04:00.0",
        "12345678",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    assert!(matches!(action, LockdownAction::Lock { .. }));

    // Test unlock subcommand
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "unlock",
        "04:00.0",
        "12345678",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    assert!(matches!(action, LockdownAction::Unlock { .. }));

    // Test set-key subcommand
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "set-key",
        "04:00.0",
        "12345678",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    assert!(matches!(action, LockdownAction::SetKey { .. }));
}

#[test]
fn test_dry_run_flag_parsing() {
    // Test that dry-run flag is parsed correctly
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "status",
        "04:00.0",
        "--dry-run",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    if let LockdownAction::Status { dry_run, .. } = action {
        assert!(dry_run);
    }
}

#[test]
fn test_output_formats() {
    // Test JSON format
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "status",
        "04:00.0",
        "--format",
        "json",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    if let LockdownAction::Status { format, .. } = action {
        assert!(matches!(format, OutputFormat::Json));
    }

    // Test YAML format
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "status",
        "04:00.0",
        "--format",
        "yaml",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    if let LockdownAction::Status { format, .. } = action {
        assert!(matches!(format, OutputFormat::Yaml));
    }
}

#[test]
fn test_positional_arguments() {
    // Test that device_id is parsed as positional argument.
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "lock",
        "test:device:id",
        "12345678",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    if let LockdownAction::Lock { device_id, key, .. } = action {
        assert_eq!(device_id, "test:device:id");
        assert_eq!(key, "12345678");
    }

    // Test that key is parsed as positional argument
    let cli = Cli::try_parse_from([
        "mlxconfig-lockdown",
        "lockdown",
        "unlock",
        "04:00.0",
        "abcdef01",
    ])
    .unwrap();

    let Commands::Lockdown { action } = cli.command;
    if let LockdownAction::Unlock { device_id, key, .. } = action {
        assert_eq!(device_id, "04:00.0");
        assert_eq!(key, "abcdef01");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_run_cli_with_dry_run() {
        // Test that dry-run commands work end-to-end
        let cli = Cli::try_parse_from([
            "mlxconfig-lockdown",
            "lockdown",
            "status",
            "fake_device",
            "--dry-run",
        ])
        .unwrap();

        // This should succeed because dry-run just prints what would be executed
        let result = run_cli(cli);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_cli_with_fake_device() {
        // This will fail since we don't have flint set up, but we can test
        // that the CLI structure works
        let cli = Cli::try_parse_from(["mlxconfig-lockdown", "lockdown", "status", "fake_device"])
            .unwrap();

        // This should fail with some kind of error, not a parsing error
        let result = run_cli(cli);
        assert!(result.is_err());

        // Should be some kind of flint-related error (could be CommandFailed, FlintNotFound, or others)
        assert!(result.is_err(), "Expected an error when using fake device");
    }

    #[test]
    fn test_all_subcommands_with_fake_device() {
        let test_cases = vec![
            vec![
                "mlxconfig-lockdown",
                "lockdown",
                "lock",
                "fake_device",
                "12345678",
                "--dry-run",
            ],
            vec![
                "mlxconfig-lockdown",
                "lockdown",
                "unlock",
                "fake_device",
                "12345678",
                "--dry-run",
            ],
            vec![
                "mlxconfig-lockdown",
                "lockdown",
                "status",
                "fake_device",
                "--dry-run",
            ],
            vec![
                "mlxconfig-lockdown",
                "lockdown",
                "set-key",
                "fake_device",
                "12345678",
                "--dry-run",
            ],
        ];

        for args in test_cases {
            let cli = Cli::try_parse_from(args.clone()).unwrap();
            let result = run_cli(cli);
            // Dry-run commands should succeed (they just print to stdout)
            assert!(result.is_ok(), "Failed for args: {args:?}");
        }
    }
}
