/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::cmp::Ordering;

use eyre::Context;
use toml_edit::{DocumentMut, Formatted, InlineTable, Item, Value};
use walkdir::WalkDir;

/// For all Cargo.toml files in the repository, take any dependencies and move their version
/// specification to the toplevel (workspace) Cargo.toml, and change them to `{ workspace = true }`.
/// This is so we don't have multiple versions of the same dependency throughout the workspace.
pub fn move_deps_to_workspace() -> eyre::Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let workspace_cargo_toml_path = cwd.join("Cargo.toml");
    let workspace_cargo_toml_string = std::fs::read_to_string(&workspace_cargo_toml_path)?;

    // The toplevel workspace cargo.toml
    let mut workspace_cargo_toml = workspace_cargo_toml_string.parse::<DocumentMut>()?;

    // Find any Cargo.toml file throughout the workspace, excluding the toplevel one
    let non_workspace_cargo_tomls = WalkDir::new(cwd)
        .into_iter()
        .filter_entry(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|name| !name.starts_with("."))
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|name| name.eq("Cargo.toml"))
        })
        .filter_map(|e| e.path().canonicalize().ok())
        // Skip workspace Cargo.toml
        .filter(|p| p != &workspace_cargo_toml_path)
        .collect::<Vec<_>>();

    for toml_path in &non_workspace_cargo_tomls {
        let contents = std::fs::read_to_string(toml_path)?;
        let mut document = contents.parse::<DocumentMut>()?;

        for deptype in ["dependencies", "dev-dependencies"] {
            let Some(deps) = document.get_mut(deptype).and_then(|v| v.as_table_mut()) else {
                continue;
            };

            for (dep_name, dep) in deps.iter_mut() {
                let dep_line_prefix = format!("{dep_name} = ");
                if contents.lines().any(|l| {
                    l.starts_with(&dep_line_prefix) && l.contains("move-deps-to-workspace:ignore")
                }) {
                    println!("Ignoring dep {} in {}", dep_name, toml_path.display());
                    continue;
                }

                if let Some(dep) = dep.as_inline_table_mut() {
                    let clear_default_features = dep
                        .get("default-features")
                        .as_ref()
                        .map(|v| v.as_bool().is_some_and(|b| !b))
                        .unwrap_or(false);

                    let Some(version) = dep
                        .get_mut("version")
                        .and_then(|v| v.as_str().map(VersionStr::from))
                    else {
                        continue;
                    };

                    specify_version(
                        &mut workspace_cargo_toml,
                        dep_name.get(),
                        version,
                        clear_default_features,
                    )
                    .with_context(|| {
                        format!(
                            "error specifying version for {} in toplevel toml",
                            dep_name.get()
                        )
                    })?;

                    dep.remove("version");
                    dep.insert("workspace", Value::Boolean(Formatted::new(true)));
                } else if let Some(version) = dep.as_str().map(VersionStr::from) {
                    specify_version(&mut workspace_cargo_toml, dep_name.get(), version, false)
                        .with_context(|| {
                            format!(
                                "error specifying version for {} in toplevel toml",
                                dep_name.get()
                            )
                        })?;

                    let mut table = InlineTable::new();
                    table.insert("workspace", Value::Boolean(Formatted::new(true)));
                    *dep = Item::Value(Value::InlineTable(table));
                };
            }
        }

        let new_contents = document.to_string();
        if new_contents != contents {
            println!("Writing new {}", toml_path.display());
            std::fs::write(toml_path, new_contents.as_bytes())
                .with_context(|| format!("Error writing to {}", toml_path.display()))?;
        }
    }

    let new_contents = workspace_cargo_toml.to_string();
    if new_contents != workspace_cargo_toml_string {
        println!("Writing new {}", workspace_cargo_toml_path.display());
        std::fs::write(
            &workspace_cargo_toml_path,
            workspace_cargo_toml.to_string().as_bytes(),
        )
        .with_context(|| format!("Error writing to {}", workspace_cargo_toml_path.display()))?;
    }

    Ok(())
}

fn specify_version(
    toml: &mut DocumentMut,
    dep_name: &str,
    new_version: VersionStr<'_>,
    clear_default_features: bool,
) -> eyre::Result<()> {
    let Some(deps) = toml["workspace"]["dependencies"].as_table_mut() else {
        return Err(eyre::eyre!(
            "no dependencies section in toplevel Cargo.toml"
        ));
    };

    let dep = deps
        .entry(dep_name)
        .or_insert_with(|| Item::Value(new_version.0.into()));

    if let Some(table) = dep.as_inline_table_mut() {
        let is_newer = table
            .get("version")
            .and_then(|v| VersionStr::try_from(v).ok())
            .is_none_or(|current| new_version > current);
        if is_newer {
            table.insert("version", new_version.0.into());
        }
        if clear_default_features {
            table.insert("default-features", Value::Boolean(Formatted::new(false)));
        }
    } else if let Some(existing_version) = dep.as_str() {
        let is_newer = new_version > VersionStr::from(existing_version);
        if clear_default_features {
            let mut table = InlineTable::new();
            table.insert("default-features", Value::Boolean(Formatted::new(false)));
            table.insert("version", new_version.0.into());
            *dep = Item::Value(Value::InlineTable(table));
        } else if is_newer {
            *dep = Item::Value(new_version.0.into());
        }
    } else {
        eprintln!("Invalid dependency in toplevel Cargo.toml: {dep_name}");
    }

    Ok(())
}

#[derive(Copy, Clone)]
struct VersionStr<'a>(&'a str);

impl<'a> From<&'a str> for VersionStr<'a> {
    fn from(s: &'a str) -> Self {
        VersionStr(s)
    }
}

impl<'a> TryFrom<&'a toml_edit::Value> for VersionStr<'a> {
    type Error = eyre::Error;
    fn try_from(v: &'a toml_edit::Value) -> Result<VersionStr<'a>, Self::Error> {
        let Some(s) = v.as_str() else {
            return Err(eyre::eyre!("value is not a string"));
        };
        Ok(VersionStr(s))
    }
}

impl<'a> PartialEq<VersionStr<'a>> for VersionStr<'a> {
    fn eq(&self, other: &VersionStr) -> bool {
        self.0 == other.0
    }
}

impl<'a> PartialOrd<VersionStr<'a>> for VersionStr<'a> {
    fn partial_cmp(&self, other: &VersionStr) -> Option<Ordering> {
        let a_components = self
            .0
            .split(".")
            .filter_map(|s| {
                s.replace(|c: char| !c.is_ascii_digit(), "")
                    .parse::<usize>()
                    .ok()
            })
            .collect::<Vec<_>>();
        let b_components = other
            .0
            .split(".")
            .filter_map(|s| {
                s.replace(|c: char| !c.is_ascii_digit(), "")
                    .parse::<usize>()
                    .ok()
            })
            .collect::<Vec<_>>();

        for i in 0..a_components.len().min(b_components.len()) {
            if a_components[i] > b_components[i] {
                return Some(Ordering::Greater);
            } else if a_components[i] < b_components[i] {
                return Some(Ordering::Less);
            }
        }

        Some(Ordering::Equal)
    }
}
