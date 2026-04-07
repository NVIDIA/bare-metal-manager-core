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
use std::collections::HashSet;

use prettytable::{Row, Table};
use rpc::Metadata;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};

use crate::{async_write, async_writeln};

/// Display metadata (name, description, labels) in the
/// requested output format. Shared across machine, rack,
/// switch, and power shelf metadata show commands.
pub(crate) async fn display_metadata(
    output_file: &mut Box<dyn tokio::io::AsyncWrite + Unpin>,
    output_format: &OutputFormat,
    metadata: &Metadata,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::AsciiTable => {
            async_writeln!(output_file, "Name        : {}", metadata.name)?;
            async_writeln!(output_file, "Description : {}", metadata.description)?;
            let mut table = Table::new();
            table.set_titles(Row::from(vec!["Key", "Value"]));
            for l in &metadata.labels {
                table.add_row(Row::from(vec![&l.key, l.value.as_deref().unwrap_or("")]));
            }
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::NotImplemented(
                "CSV formatted output".to_string(),
            ));
        }
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(&metadata)?)?
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }
    Ok(())
}

/// Shared metadata mutation helpers for the `metadata` subcommands.
///
/// These are used by machine, rack, switch, and power shelf to
/// implement `metadata set`, `metadata add-label`, and
/// `metadata remove-labels`. Each caller fetches its entity,
/// passes `entity.metadata` to one of these, then sends the
/// result to the entity's `update_*_metadata` RPC.
///
/// Things were so boilerplate it was either do a series of
/// macros, or make some helper functions, and since most of
/// the macro-able stuff was related to metadata mutation,
/// these were created.
///
/// Apply a name and/or description update to an entity's metadata.
/// Fields that are `None` are left unchanged.
pub(crate) fn apply_set(
    metadata: Option<Metadata>,
    name: Option<String>,
    description: Option<String>,
) -> CarbideCliResult<Metadata> {
    let mut metadata = metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Entity does not carry Metadata that can be patched".into())
    })?;
    if let Some(name) = name {
        metadata.name = name;
    }
    if let Some(description) = description {
        metadata.description = description;
    }
    Ok(metadata)
}

/// Add a label to an entity's metadata. If a label
/// with the same key already exists, it is replaced
/// with the new value.
pub(crate) fn apply_add_label(
    metadata: Option<Metadata>,
    key: String,
    value: Option<String>,
) -> CarbideCliResult<Metadata> {
    let mut metadata = metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Entity does not carry Metadata that can be patched".into())
    })?;
    metadata.labels.retain_mut(|l| l.key != key);
    metadata.labels.push(rpc::forge::Label { key, value });
    Ok(metadata)
}

/// Remove one or more labels from an entity's
/// metadata by key. Keys that don't exist are
/// silently ignored.
pub(crate) fn apply_remove_labels(
    metadata: Option<Metadata>,
    keys: Vec<String>,
) -> CarbideCliResult<Metadata> {
    let mut metadata = metadata.ok_or_else(|| {
        CarbideCliError::GenericError("Entity does not carry Metadata that can be patched".into())
    })?;
    let removed: HashSet<String> = keys.into_iter().collect();
    metadata.labels.retain(|l| !removed.contains(&l.key));
    Ok(metadata)
}

/// Format an entity's labels as quoted `"key:value"`
/// strings for display in list views (e.g. the machine
/// list table). Returns an empty vec if metadata is
/// None or has no labels.
pub(crate) fn get_nice_labels_from_rpc_metadata(metadata: Option<&Metadata>) -> Vec<String> {
    metadata
        .map(|m| {
            m.labels
                .iter()
                .map(|label| {
                    let key = &label.key;
                    let value = label.value.as_deref().unwrap_or_default();
                    format!("\"{key}:{value}\"")
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse user-provided label strings (in `key:value`
/// format) into RPC Label structs. A label without
/// a `:` separator is treated as a key-only label
/// with no value.
pub(crate) fn parse_rpc_labels(labels: Vec<String>) -> Vec<rpc::forge::Label> {
    labels
        .into_iter()
        .map(|label| match label.split_once(':') {
            Some((k, v)) => rpc::forge::Label {
                key: k.trim().to_string(),
                value: Some(v.trim().to_string()),
            },
            None => rpc::forge::Label {
                key: if label.contains(char::is_whitespace) {
                    label.trim().to_string()
                } else {
                    // avoid allocations on the happy path
                    label
                },
                value: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(key: &str, value: Option<&str>) -> rpc::forge::Label {
        rpc::forge::Label {
            key: key.to_string(),
            value: value.map(str::to_string),
        }
    }

    fn metadata_with(name: &str, desc: &str, labels: Vec<rpc::forge::Label>) -> Metadata {
        Metadata {
            name: name.to_string(),
            description: desc.to_string(),
            labels,
        }
    }

    // apply_set tests

    #[test]
    fn apply_set_updates_name() {
        let m = metadata_with("old", "desc", vec![]);
        let result = apply_set(Some(m), Some("new".into()), None).unwrap();
        assert_eq!(result.name, "new");
        assert_eq!(result.description, "desc");
    }

    #[test]
    fn apply_set_updates_description() {
        let m = metadata_with("name", "old", vec![]);
        let result = apply_set(Some(m), None, Some("new".into())).unwrap();
        assert_eq!(result.name, "name");
        assert_eq!(result.description, "new");
    }

    #[test]
    fn apply_set_none_leaves_unchanged() {
        let m = metadata_with("name", "desc", vec![]);
        let result = apply_set(Some(m), None, None).unwrap();
        assert_eq!(result.name, "name");
        assert_eq!(result.description, "desc");
    }

    #[test]
    fn apply_set_missing_metadata_errors() {
        assert!(apply_set(None, Some("x".into()), None).is_err());
    }

    // apply_add_label tests

    #[test]
    fn apply_add_label_adds_new() {
        let m = metadata_with("n", "", vec![]);
        let result = apply_add_label(Some(m), "env".into(), Some("prod".into())).unwrap();
        assert_eq!(result.labels.len(), 1);
        assert_eq!(result.labels[0].key, "env");
        assert_eq!(result.labels[0].value, Some("prod".to_string()));
    }

    #[test]
    fn apply_add_label_replaces_existing() {
        let m = metadata_with("n", "", vec![label("env", Some("staging"))]);
        let result = apply_add_label(Some(m), "env".into(), Some("prod".into())).unwrap();
        assert_eq!(result.labels.len(), 1);
        assert_eq!(result.labels[0].value, Some("prod".to_string()));
    }

    #[test]
    fn apply_add_label_preserves_others() {
        let m = metadata_with("n", "", vec![label("team", Some("infra"))]);
        let result = apply_add_label(Some(m), "env".into(), Some("prod".into())).unwrap();
        assert_eq!(result.labels.len(), 2);
    }

    #[test]
    fn apply_add_label_missing_metadata_errors() {
        assert!(apply_add_label(None, "k".into(), None).is_err());
    }

    // apply_remove_labels tests

    #[test]
    fn apply_remove_labels_removes_matching() {
        let m = metadata_with("n", "", vec![label("a", None), label("b", None)]);
        let result = apply_remove_labels(Some(m), vec!["a".into()]).unwrap();
        assert_eq!(result.labels.len(), 1);
        assert_eq!(result.labels[0].key, "b");
    }

    #[test]
    fn apply_remove_labels_ignores_missing_keys() {
        let m = metadata_with("n", "", vec![label("a", None)]);
        let result = apply_remove_labels(Some(m), vec!["nonexistent".into()]).unwrap();
        assert_eq!(result.labels.len(), 1);
    }

    #[test]
    fn apply_remove_labels_missing_metadata_errors() {
        assert!(apply_remove_labels(None, vec!["k".into()]).is_err());
    }
}
