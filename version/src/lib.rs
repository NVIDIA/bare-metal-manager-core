/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::process::Command;

/// Set build script environment variables. Call this from a build script.
pub fn build() {
    git_allow();
    println!(
        "cargo:rustc-env=FORGE_BUILD_USER={}",
        option_env!("USER").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=FORGE_BUILD_HOSTNAME={}",
        option_env!("HOSTNAME").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=FORGE_BUILD_DATE={}",
        run("date", &["--iso-8601", "--utc"])
    );
    println!(
        "cargo:rustc-env=FORGE_BUILD_RUSTC_VERSION={}",
        run(option_env!("RUSTC").unwrap_or("rustc"), &["--version"])
    );

    // For these two in CI we use the env var, locally we query git

    println!(
        "cargo:warning=CI_COMMIT_SHORT_SHA '{:?}', VERSION '{:?}'",
        option_env!("CI_COMMIT_SHORT_SHA"),
        option_env!("VERSION"),
    );

    let sha = option_env!("CI_COMMIT_SHORT_SHA")
        .map(String::from)
        .unwrap_or_else(|| run("git", &["rev-parse", "--short=8", "HEAD"]));
    println!("cargo:rustc-env=FORGE_BUILD_GIT_HASH={sha}");

    let build_version = option_env!("VERSION")
        .map(String::from)
        .unwrap_or_else(|| run("git", &["describe", "--tags", "--first-parent", "--always"]));
    println!("cargo:rustc-env=FORGE_BUILD_GIT_TAG={build_version}");

    // Only re-calculate all of this when there's a new commit
    println!("cargo:rerun-if-changed=.git/HEAD");
}

// If the current user is not the owner of the repo root (containing .git), then
// git will exit with status 128 "fatal: detected dubious ownership".
// This happens in containers.
// Exit code 128 means many things, this just handles one of them.
//
// "git config --add" is not idempotent, so only do this if we have to.
fn git_allow() {
    match Command::new("git").arg("status").status() {
        Err(err) => {
            println!("cargo:warning=build.rs error running 'git status': {err}.")
        }
        Ok(status) => match status.code() {
            Some(128) => git_mark_safe_directory(),
            Some(_) => {}
            None => {}
        },
    }
}

fn git_mark_safe_directory() {
    let repo_root = option_env!("REPO_ROOT")
        .or(option_env!("CONTAINER_REPO_ROOT"))
        .unwrap_or(r#"*"#);
    run(
        "git",
        &["config", "--global", "--add", "safe.directory", repo_root],
    );
}

/// Run a command from a build script returning it's stdout, logging errors with cargo:warning
fn run(cmd: &str, args: &[&str]) -> String {
    let output = match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if !output.status.success() {
                println!(
                    "cargo:warning=build.rs failed running '{cmd} {}': '{output:?}'",
                    args.join(" ")
                );
                return String::new();
            }
            output
        }
        Err(err) => {
            println!(
                "cargo:warning=build.rs error running '{cmd} {}': {err}.",
                args.join(" ")
            );
            return String::new();
        }
    };
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Version as a string. `version::build()` must have been called previously in build script.
#[macro_export]
macro_rules! version {
    () => {
        format!(
            "build_version={}, build_date={}, git_sha={}, rust_version={}, build_user={}, build_hostname={}",
            option_env!("FORGE_BUILD_GIT_TAG").unwrap_or_default(),
            option_env!("FORGE_BUILD_DATE").unwrap_or_default(),
            option_env!("FORGE_BUILD_GIT_HASH").unwrap_or_default(),
            option_env!("FORGE_BUILD_RUSTC_VERSION").unwrap_or_default(),
            option_env!("FORGE_BUILD_USER").unwrap_or_default(),
            option_env!("FORGE_BUILD_HOSTNAME").unwrap_or_default(),
        );
    };
}
