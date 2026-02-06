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

use std::path::Path;
use std::process::Command;

/// Set build script environment variables. Call this from a build script.
pub fn build() {
    // TODO: Remove after migration to new CARBIDE_ naming
    println!(
        "cargo:rustc-env=FORGE_BUILD_USER={}",
        option_env!("USER").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=CARBIDE_BUILD_USER={}",
        option_env!("USER").unwrap_or_default()
    );
    // TODO: Remove after migration to new CARBIDE_ naming
    println!(
        "cargo:rustc-env=FORGE_BUILD_HOSTNAME={}",
        option_env!("HOSTNAME").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=CARBIDE_BUILD_HOSTNAME={}",
        option_env!("HOSTNAME").unwrap_or_default()
    );
    // TODO: Remove after migration to new CARBIDE_ naming
    println!(
        "cargo:rustc-env=FORGE_BUILD_DATE={}",
        run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]) // like 'date --iso-8601=seconds --utc' but portable across GNU/BSD
    );
    println!(
        "cargo:rustc-env=CARBIDE_BUILD_DATE={}",
        run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]) // like 'date --iso-8601=seconds --utc' but portable across GNU/BSD
    );
    // TODO: Remove after migration to new CARBIDE_ naming
    println!(
        "cargo:rustc-env=FORGE_BUILD_RUSTC_VERSION={}",
        run(option_env!("RUSTC").unwrap_or("rustc"), &["--version"])
    );
    println!(
        "cargo:rustc-env=CARBIDE_BUILD_RUSTC_VERSION={}",
        run(option_env!("RUSTC").unwrap_or("rustc"), &["--version"])
    );

    // In a git worktree in a container (local dev) none of the git commands will work because
    // the real git directory isn't mounted.
    let can_git = Command::new("git")
        .args(["rev-parse"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !can_git {
        println!("cargo:warning=No git, version will be blank");
        // still define it so that we can read it in a build time macro
        // TODO: Remove after migration to new CARBIDE_ naming
        println!("cargo:rustc-env=FORGE_BUILD_GIT_TAG=");
        println!("cargo:rustc-env=CARBIDE_BUILD_GIT_HASH=");
        return;
    }

    git_allow();

    // For these two in CI we use the env var, locally we query git

    let sha = option_env!("CI_COMMIT_SHORT_SHA")
        .map(String::from)
        .unwrap_or_else(|| run("git", &["rev-parse", "--short=8", "HEAD"]));
    // TODO: Remove after migration to new CARBIDE_ naming
    println!("cargo:rustc-env=FORGE_BUILD_GIT_HASH={sha}");
    println!("cargo:rustc-env=CARBIDE_BUILD_GIT_HASH={sha}");

    let build_version = option_env!("VERSION").map(String::from).unwrap_or_else(|| {
        run(
            "git",
            &["describe", "--tags", "--first-parent", "--always", "--long"],
        )
    });
    // TODO: Remove after migration to new CARBIDE_ naming
    println!("cargo:rustc-env=FORGE_BUILD_GIT_TAG={build_version}");
    println!("cargo:rustc-env=CARBIDE_BUILD_GIT_TAG={build_version}");

    // Only re-calculate all of this when there's a new commit... but use an env var to allow
    // avoiding rebuilds when the commit hash changes. (This is good for local development iteration
    // loops when we want to avoid recompiling and when we don't really care if the generated
    // version is stale.)
    // TODO: Remove after migration to new CARBIDE_ naming
    if std::env::var("FORGE_VERSION_AVOID_REBUILD").is_err()
        || std::env::var("CARBIDE_VERSION_AVOID_REBUILD").is_err()
    {
        let git_query_head =
            run("git", &["rev-parse", "--path-format=absolute", "--git-dir"]) + "/HEAD";
        let git_head = if Path::new(&git_query_head).exists() {
            // dev
            git_query_head
        } else {
            // CI
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../.git/HEAD").to_string()
        };

        // Check that this file is still relative to the repository root where we expect.
        // If it isn't, then rerun-if-changed is wrong - and we will rebuilt the version
        // crate and all dependents on each `cargo build`
        assert!(
            std::path::Path::new(&git_head).exists(),
            "Git HEAD not found at {git_head}. Adjust location to avoid double compilation"
        );

        println!("cargo:rerun-if-changed={git_head}");
    }
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

/// Run a command from a build script returning its stdout, logging errors with cargo:warning
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

/// Individual parts of the version. Usage:: forge_version::v!(build_version)
/// If that part is not present expands to an empty &str
// TODO: Change to CARBIDE_
#[macro_export]
macro_rules! v {
    (build_version) => {
        option_env!("FORGE_BUILD_GIT_TAG").unwrap_or_default()
    };
    (build_date) => {
        option_env!("FORGE_BUILD_DATE").unwrap_or_default()
    };
    (git_sha) => {
        option_env!("FORGE_BUILD_GIT_HASH").unwrap_or_default()
    };
    (rust_version) => {
        option_env!("FORGE_BUILD_RUSTC_VERSION").unwrap_or_default()
    };
    (build_user) => {
        option_env!("FORGE_BUILD_USER").unwrap_or_default()
    };
    (build_hostname) => {
        option_env!("FORGE_BUILD_HOSTNAME").unwrap_or_default()
    };
}

/// Same a v! but expands to a literal. That allows using it in `concat!` macro.
/// Panics if the part is not present. Prefer `v!` above.
// TODO: Change to CARBIDE_
#[macro_export]
macro_rules! literal {
    (build_version) => {
        env!("FORGE_BUILD_GIT_TAG")
    };
    (build_date) => {
        env!("FORGE_BUILD_DATE")
    };
    (git_sha) => {
        env!("FORGE_BUILD_GIT_HASH")
    };
    (rust_version) => {
        env!("FORGE_BUILD_RUSTC_VERSION")
    };
    (build_user) => {
        env!("FORGE_BUILD_USER")
    };
    (build_hostname) => {
        env!("FORGE_BUILD_HOSTNAME")
    };
}

/// Version as a string. `version::build()` must have been called previously in build script.
// TODO: Change to CARBIDE_
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
