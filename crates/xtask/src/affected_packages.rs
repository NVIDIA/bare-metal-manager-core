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
//! Selects the Rust workspace packages that CI must check for a Git change.
//!
//! The `affected-packages` command finds the merge-base of `HEAD` and the revision
//! passed through `--base` (defaulting to `origin/main`), then reads every changed,
//! deleted, copied, and renamed path between that merge-base and `HEAD`. It uses
//! `cargo metadata` to map those paths to their owning workspace packages and
//! expands the selection with all transitive workspace dependents. Cargo's resolved
//! dependency graph includes normal, build, and development dependencies with all
//! workspace features enabled, matching the feature scope used by the CI checks.
//!
//! Version-qualified Cargo package selectors are written to standard output, one
//! per line in sorted order, so callers can turn them into `-p/--package` arguments
//! without ambiguity when a dependency has the same name as a workspace package.
//! When the command selects the full workspace, it writes the reason to standard
//! error while keeping standard output machine-readable.
//! The command selects the entire workspace when a path is unsafe or cannot be
//! mapped to a workspace package, the dependency graph is incomplete, no paths
//! changed, or a global input such as the root Cargo files, toolchain configuration,
//! custom lints, xtask code, or CI configuration changed. This conservative fallback
//! ensures CI never silently skips a package when the narrower selection cannot be
//! proven correct.
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, PackageId};
use eyre::{Context, ContextCompat, bail};

#[derive(Debug)]
struct WorkspacePackage {
    id: PackageId,
    cargo_selector: String,
    root: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum Selection {
    All(FullWorkspaceReason),
    Packages(BTreeSet<String>),
}

#[derive(Debug, PartialEq, Eq)]
enum FullWorkspaceReason {
    GlobalPath(String),
    UnsafePath(String),
    UnmappedPath(String),
    EmptyDiff,
    MalformedDiff,
    IncompleteDependencyGraph,
}

impl fmt::Display for FullWorkspaceReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlobalPath(path) => write!(formatter, "global path changed: {path}"),
            Self::UnsafePath(path) => {
                write!(
                    formatter,
                    "changed path is not a safe relative path: {path}"
                )
            }
            Self::UnmappedPath(path) => write!(
                formatter,
                "changed path does not map to a workspace package: {path}"
            ),
            Self::EmptyDiff => formatter.write_str("no changed paths found"),
            Self::MalformedDiff => {
                formatter.write_str("Git diff output was malformed or non-UTF-8")
            }
            Self::IncompleteDependencyGraph => {
                formatter.write_str("Cargo dependency graph was incomplete")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ChangedPaths {
    Paths(Vec<String>),
    MalformedDiff,
}

pub fn run(base: &str) -> eyre::Result<()> {
    let metadata = workspace_metadata()?;
    let workspace_packages = workspace_packages(&metadata)?;
    let all_package_selectors = all_package_selectors(&workspace_packages);
    let changed_paths = changed_paths(&metadata.workspace_root, base)?;

    let selection = match changed_paths {
        ChangedPaths::MalformedDiff => Selection::All(FullWorkspaceReason::MalformedDiff),
        ChangedPaths::Paths(changed_paths) => reverse_dependencies(&metadata, &workspace_packages)
            .map(|reverse_dependencies| {
                select_affected(&changed_paths, &workspace_packages, &reverse_dependencies)
            })
            .unwrap_or(Selection::All(
                FullWorkspaceReason::IncompleteDependencyGraph,
            )),
    };

    let package_selectors = match selection {
        Selection::All(reason) => {
            eprintln!("affected-packages: selecting full workspace: {reason}");
            all_package_selectors
        }
        Selection::Packages(package_selectors) => package_selectors,
    };

    for package_selector in package_selectors {
        println!("{package_selector}");
    }

    Ok(())
}

fn workspace_metadata() -> eyre::Result<Metadata> {
    let metadata = MetadataCommand::new()
        .features(CargoOpt::AllFeatures)
        .other_options(vec!["--locked".to_string()])
        .exec()
        .context("failed to run cargo metadata")?;
    Ok(metadata)
}

fn workspace_packages(metadata: &Metadata) -> eyre::Result<Vec<WorkspacePackage>> {
    metadata
        .workspace_members
        .iter()
        .map(|member| {
            let package = metadata
                .packages
                .iter()
                .find(|package| &package.id == member)
                .with_context(|| {
                    format!("workspace member {member} missing from cargo metadata")
                })?;
            let manifest_dir = package
                .manifest_path
                .parent()
                .context("workspace package manifest has no parent directory")?;
            let root = manifest_dir
                .strip_prefix(&metadata.workspace_root)
                .with_context(|| {
                    format!(
                        "package {} is outside workspace root {}",
                        package.name,
                        metadata.workspace_root.display()
                    )
                })?
                .to_path_buf();

            Ok(WorkspacePackage {
                id: member.clone(),
                cargo_selector: format!("{}@{}", package.name, package.version),
                root,
            })
        })
        .collect()
}

fn reverse_dependencies(
    metadata: &Metadata,
    workspace_packages: &[WorkspacePackage],
) -> Option<HashMap<PackageId, BTreeSet<PackageId>>> {
    let resolve = metadata.resolve.as_ref()?;
    let workspace_ids = workspace_packages
        .iter()
        .map(|package| package.id.clone())
        .collect::<HashSet<_>>();
    let mut reverse_dependencies = workspace_ids
        .iter()
        .cloned()
        .map(|id| (id, BTreeSet::new()))
        .collect::<HashMap<_, _>>();

    for node in &resolve.nodes {
        if !workspace_ids.contains(&node.id) {
            continue;
        }

        for dependency in &node.dependencies {
            if workspace_ids.contains(dependency) {
                reverse_dependencies
                    .get_mut(dependency)?
                    .insert(node.id.clone());
            }
        }
    }

    // A missing workspace node means the graph is incomplete. Fall back to all.
    if workspace_ids
        .iter()
        .any(|id| !resolve.nodes.iter().any(|node| &node.id == id))
    {
        return None;
    }

    Some(reverse_dependencies)
}

fn select_affected(
    changed_paths: &[String],
    workspace_packages: &[WorkspacePackage],
    reverse_dependencies: &HashMap<PackageId, BTreeSet<PackageId>>,
) -> Selection {
    if changed_paths.is_empty() {
        return Selection::All(FullWorkspaceReason::EmptyDiff);
    }
    if let Some(path) = changed_paths.iter().find(|path| is_global_path(path)) {
        return Selection::All(FullWorkspaceReason::GlobalPath(path.clone()));
    }

    let mut affected = BTreeSet::new();
    for changed_path in changed_paths {
        let Some(path) = safe_relative_path(changed_path) else {
            return Selection::All(FullWorkspaceReason::UnsafePath(changed_path.clone()));
        };
        let Some(package) = owning_package(path, workspace_packages) else {
            return Selection::All(FullWorkspaceReason::UnmappedPath(changed_path.clone()));
        };
        affected.insert(package.id.clone());
    }

    let mut queue = affected.iter().cloned().collect::<VecDeque<_>>();
    while let Some(package) = queue.pop_front() {
        let Some(dependents) = reverse_dependencies.get(&package) else {
            return Selection::All(FullWorkspaceReason::IncompleteDependencyGraph);
        };
        for dependent in dependents {
            if affected.insert(dependent.clone()) {
                queue.push_back(dependent.clone());
            }
        }
    }

    let selectors_by_id = workspace_packages
        .iter()
        .map(|package| (&package.id, &package.cargo_selector))
        .collect::<HashMap<_, _>>();
    let package_selectors = affected
        .iter()
        .map(|id| selectors_by_id.get(id).map(|selector| (*selector).clone()))
        .collect::<Option<BTreeSet<_>>>();

    package_selectors
        .map(Selection::Packages)
        .unwrap_or(Selection::All(
            FullWorkspaceReason::IncompleteDependencyGraph,
        ))
}

fn owning_package<'a>(
    path: &Path,
    workspace_packages: &'a [WorkspacePackage],
) -> Option<&'a WorkspacePackage> {
    workspace_packages
        .iter()
        .filter(|package| path.starts_with(&package.root))
        .max_by_key(|package| package.root.components().count())
}

fn safe_relative_path(path: &str) -> Option<&Path> {
    let path = Path::new(path);
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Some(path)
    } else {
        None
    }
}

fn is_global_path(path: &str) -> bool {
    const GLOBAL_FILES: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
        "Makefile",
        "Makefile.toml",
        "Makefile-build.toml",
        "Makefile-package.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
    ];
    const GLOBAL_DIRECTORIES: &[&str] = &[
        ".cargo/",
        ".github/",
        ".gitlab/",
        "crates/xtask/",
        "include/",
        "lints/",
    ];

    GLOBAL_FILES.contains(&path)
        || path.starts_with(".gitlab-ci")
        || GLOBAL_DIRECTORIES
            .iter()
            .any(|directory| path.starts_with(directory))
}

fn all_package_selectors(workspace_packages: &[WorkspacePackage]) -> BTreeSet<String> {
    workspace_packages
        .iter()
        .map(|package| package.cargo_selector.clone())
        .collect()
}

fn changed_paths(workspace_root: &Path, base: &str) -> eyre::Result<ChangedPaths> {
    let merge_base = git_output(workspace_root, ["merge-base", base, "HEAD"])?;
    let merge_base = String::from_utf8(merge_base.stdout)
        .context("git merge-base returned a non-UTF-8 revision")?;
    let merge_base = merge_base.trim();
    if merge_base.is_empty() {
        bail!("git merge-base returned an empty revision");
    }

    let diff = git_output(
        workspace_root,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            merge_base,
            "HEAD",
            "--",
        ],
    )?;

    // Malformed or non-UTF-8 Git output is uncertain, so select every package.
    Ok(parsed_changed_paths(&diff.stdout))
}

fn parsed_changed_paths(output: &[u8]) -> ChangedPaths {
    parse_name_status(output)
        .map(ChangedPaths::Paths)
        .unwrap_or(ChangedPaths::MalformedDiff)
}

fn git_output<const N: usize>(workspace_root: &Path, args: [&str; N]) -> eyre::Result<Output> {
    let output = Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()
        .context("failed to run git")?;
    if !output.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn parse_name_status(output: &[u8]) -> Option<Vec<String>> {
    if output.is_empty() {
        return Some(Vec::new());
    }

    let fields = output
        .strip_suffix(&[0])?
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    let mut index = 0;

    while index < fields.len() {
        let status = std::str::from_utf8(fields[index]).ok()?;
        index += 1;
        if status.is_empty() || index >= fields.len() {
            return None;
        }

        let path_count = if status.starts_with('R') || status.starts_with('C') {
            2
        } else {
            1
        };
        if index + path_count > fields.len() {
            return None;
        }

        for field in &fields[index..index + path_count] {
            let path = std::str::from_utf8(field).ok()?;
            if path.is_empty() {
                return None;
            }
            paths.push(path.to_string());
        }
        index += path_count;
    }

    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_workspace_metadata_enables_every_workspace_feature() {
        // This is intentionally integration-style: synthetic dependency graphs
        // cannot prove that `CargoOpt::AllFeatures` reaches Cargo and activates
        // optional workspace dependency edges in the production metadata call.
        let metadata = workspace_metadata().unwrap();
        let resolve = metadata.resolve.as_ref().unwrap();

        for member in &metadata.workspace_members {
            let package = metadata
                .packages
                .iter()
                .find(|package| &package.id == member)
                .unwrap();
            let node = resolve
                .nodes
                .iter()
                .find(|node| &node.id == member)
                .unwrap();
            let missing_features = package
                .features
                .keys()
                .filter(|feature| !node.features.contains(feature))
                .collect::<Vec<_>>();

            assert!(
                missing_features.is_empty(),
                "package {} is missing resolved features: {missing_features:?}",
                package.name
            );
        }
    }

    fn package(id: &str, name: &str, root: &str) -> WorkspacePackage {
        WorkspacePackage {
            id: PackageId {
                repr: id.to_string(),
            },
            cargo_selector: format!("{name}@0.1.0"),
            root: PathBuf::from(root),
        }
    }

    fn fixture() -> (
        Vec<WorkspacePackage>,
        HashMap<PackageId, BTreeSet<PackageId>>,
    ) {
        let packages = vec![
            package("a", "alpha", "crates/alpha"),
            package("b", "beta", "crates/beta"),
            package("c", "gamma", "crates/gamma"),
            package("nested", "nested-tests", "crates/alpha/tests"),
        ];
        let reverse_dependencies = HashMap::from([
            (
                packages[0].id.clone(),
                BTreeSet::from([packages[1].id.clone()]),
            ),
            (
                packages[1].id.clone(),
                BTreeSet::from([packages[2].id.clone()]),
            ),
            (packages[2].id.clone(), BTreeSet::new()),
            (packages[3].id.clone(), BTreeSet::new()),
        ]);
        (packages, reverse_dependencies)
    }

    fn selected_names(selection: Selection) -> Vec<String> {
        match selection {
            Selection::Packages(packages) => packages.into_iter().collect(),
            Selection::All(reason) => panic!("expected a package selection, got: {reason}"),
        }
    }

    #[test]
    fn maps_paths_to_the_deepest_package_and_adds_transitive_dependents() {
        let (packages, reverse_dependencies) = fixture();

        assert_eq!(
            selected_names(select_affected(
                &["crates/alpha/src/lib.rs".to_string()],
                &packages,
                &reverse_dependencies,
            )),
            ["alpha@0.1.0", "beta@0.1.0", "gamma@0.1.0"]
        );
        assert_eq!(
            selected_names(select_affected(
                &["crates/alpha/tests/src/lib.rs".to_string()],
                &packages,
                &reverse_dependencies,
            )),
            ["nested-tests@0.1.0"]
        );
    }

    #[test]
    fn package_manifest_changes_select_the_package() {
        let (packages, reverse_dependencies) = fixture();

        assert_eq!(
            selected_names(select_affected(
                &["crates/beta/Cargo.toml".to_string()],
                &packages,
                &reverse_dependencies,
            )),
            ["beta@0.1.0", "gamma@0.1.0"]
        );
    }

    #[test]
    fn renamed_paths_select_both_owners() {
        let (packages, reverse_dependencies) = fixture();

        assert_eq!(
            selected_names(select_affected(
                &[
                    "crates/alpha/src/moved.rs".to_string(),
                    "crates/beta/src/moved.rs".to_string(),
                ],
                &packages,
                &reverse_dependencies,
            )),
            ["alpha@0.1.0", "beta@0.1.0", "gamma@0.1.0"]
        );
    }

    #[test]
    fn global_unmapped_unsafe_and_empty_changes_select_all_with_a_reason() {
        let (packages, reverse_dependencies) = fixture();
        let paths = [
            (
                "Cargo.toml",
                FullWorkspaceReason::GlobalPath("Cargo.toml".to_string()),
            ),
            (
                "Cargo.lock",
                FullWorkspaceReason::GlobalPath("Cargo.lock".to_string()),
            ),
            (
                "rust-toolchain.toml",
                FullWorkspaceReason::GlobalPath("rust-toolchain.toml".to_string()),
            ),
            (
                ".cargo/config.toml",
                FullWorkspaceReason::GlobalPath(".cargo/config.toml".to_string()),
            ),
            (
                "lints/carbide-lints/src/lib.rs",
                FullWorkspaceReason::GlobalPath("lints/carbide-lints/src/lib.rs".to_string()),
            ),
            (
                "crates/xtask/src/main.rs",
                FullWorkspaceReason::GlobalPath("crates/xtask/src/main.rs".to_string()),
            ),
            (
                ".github/workflows/ci.yaml",
                FullWorkspaceReason::GlobalPath(".github/workflows/ci.yaml".to_string()),
            ),
            (
                "Makefile.toml",
                FullWorkspaceReason::GlobalPath("Makefile.toml".to_string()),
            ),
            (
                "docs/readme.md",
                FullWorkspaceReason::UnmappedPath("docs/readme.md".to_string()),
            ),
            (
                "crates/deleted-package/Cargo.toml",
                FullWorkspaceReason::UnmappedPath("crates/deleted-package/Cargo.toml".to_string()),
            ),
            (
                "../Cargo.toml",
                FullWorkspaceReason::UnsafePath("../Cargo.toml".to_string()),
            ),
        ];

        for (path, reason) in paths {
            assert_eq!(
                select_affected(&[path.to_string()], &packages, &reverse_dependencies),
                Selection::All(reason),
                "path {path} should select the full workspace"
            );
        }
        assert_eq!(
            select_affected(&[], &packages, &reverse_dependencies),
            Selection::All(FullWorkspaceReason::EmptyDiff)
        );
    }

    #[test]
    fn incomplete_dependency_graph_selects_all_with_a_reason() {
        let (packages, mut reverse_dependencies) = fixture();
        reverse_dependencies.remove(&packages[0].id);

        assert_eq!(
            select_affected(
                &["crates/alpha/src/lib.rs".to_string()],
                &packages,
                &reverse_dependencies,
            ),
            Selection::All(FullWorkspaceReason::IncompleteDependencyGraph)
        );
    }

    #[test]
    fn deleted_file_in_an_existing_package_selects_its_owner() {
        let (packages, reverse_dependencies) = fixture();

        assert_eq!(
            selected_names(select_affected(
                &["crates/beta/src/deleted.rs".to_string()],
                &packages,
                &reverse_dependencies,
            )),
            ["beta@0.1.0", "gamma@0.1.0"]
        );
    }

    #[test]
    fn parses_modified_deleted_and_renamed_git_records() {
        let output = b"M\0crates/alpha/src/lib.rs\0D\0crates/beta/src/old.rs\0R100\0crates/alpha/src/from.rs\0crates/gamma/src/to.rs\0";

        assert_eq!(
            parse_name_status(output).unwrap(),
            [
                "crates/alpha/src/lib.rs",
                "crates/beta/src/old.rs",
                "crates/alpha/src/from.rs",
                "crates/gamma/src/to.rs",
            ]
        );
        assert!(parse_name_status(b"R100\0only-one-path\0").is_none());
        assert!(parse_name_status(b"M\0missing-trailing-nul").is_none());
    }

    #[test]
    fn malformed_diff_is_distinct_from_an_empty_diff() {
        assert_eq!(
            parsed_changed_paths(b"M\0missing-trailing-nul"),
            ChangedPaths::MalformedDiff
        );
        assert_eq!(parsed_changed_paths(b""), ChangedPaths::Paths(Vec::new()));
    }

    #[test]
    fn full_workspace_reasons_are_actionable() {
        let reasons = [
            (
                FullWorkspaceReason::GlobalPath("Cargo.lock".to_string()),
                "global path changed: Cargo.lock",
            ),
            (
                FullWorkspaceReason::UnsafePath("../Cargo.toml".to_string()),
                "changed path is not a safe relative path: ../Cargo.toml",
            ),
            (
                FullWorkspaceReason::UnmappedPath("docs/readme.md".to_string()),
                "changed path does not map to a workspace package: docs/readme.md",
            ),
            (FullWorkspaceReason::EmptyDiff, "no changed paths found"),
            (
                FullWorkspaceReason::MalformedDiff,
                "Git diff output was malformed or non-UTF-8",
            ),
            (
                FullWorkspaceReason::IncompleteDependencyGraph,
                "Cargo dependency graph was incomplete",
            ),
        ];

        for (reason, message) in reasons {
            assert_eq!(reason.to_string(), message);
        }
    }
}
