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

//! This checker covers fields written in the production Rust module graph,
//! including tracing calls nested in opaque macro bodies. Macro-expanded,
//! generated, and `include!`-provided syntax stays outside this source-level contract.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use carbide_observability_schema::{
    AliasConfidence, AliasTarget, FieldSurface, FieldUse, field_alias, field_definition,
    field_family, field_use, is_reserved_field, rendered_field_name, validate_field_name,
};
use clap::ValueEnum;
use eyre::{Context, bail};
use proc_macro2::{Delimiter, Group, Span, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, Field, FnArg, Item, Lit, Meta, Pat, Signature, Token, Type, UseTree};
use toml_edit::{ArrayOfTables, DocumentMut, Item as TomlItem, Table, value};

use crate::source_graph;

const BASELINE_PATH: &str = "crates/xtask/structured_log_baseline.toml";
const BASELINE_HEADER: &str = "\
# Managed by `cargo xtask check-structured-logs --update-baseline`.\n\
# New entries keep a TODO reason until somebody reviews why they remain.\n\n";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum InventoryFormat {
    Json,
    Markdown,
}

pub(crate) fn check(update_baseline: bool) -> eyre::Result<()> {
    let inventory = collect_workspace()?;
    let baseline_path = inventory.workspace_root.join(BASELINE_PATH);
    if update_baseline {
        write_baseline(&baseline_path, &inventory.findings)?;
        println!(
            "Updated {} with {} structured-log exception group(s)",
            BASELINE_PATH,
            grouped_gated_findings(&inventory.findings).len()
        );
        return Ok(());
    }

    let baseline = read_baseline(&baseline_path)?;
    let diagnostics = compare_baseline(&inventory.findings, &baseline);
    if diagnostics.is_empty() {
        println!(
            "Checked {} structured fields and {} tracing messages across {} production Rust source files",
            inventory.fields.len(),
            inventory.messages.len(),
            inventory.files_scanned
        );
        return Ok(());
    }

    for diagnostic in &diagnostics {
        eprintln!("{diagnostic}");
    }
    bail!(
        "check-structured-logs found {} baseline error(s)",
        diagnostics.len()
    )
}

pub(crate) fn inventory(format: InventoryFormat) -> eyre::Result<()> {
    let inventory = collect_workspace()?;
    match format {
        InventoryFormat::Json => print!("{}", inventory.render_json()),
        InventoryFormat::Markdown => print!("{}", inventory.render_markdown()),
    }
    Ok(())
}

fn collect_workspace() -> eyre::Result<Inventory> {
    let mut inventory = Inventory::default();
    let graph = source_graph::workspace(|workspace_root, source_path, file| {
        let path = source_path
            .strip_prefix(workspace_root)
            .unwrap_or(source_path)
            .to_path_buf();
        let mut visitor = StructuredLogVisitor {
            path: &path,
            scopes: Vec::new(),
            inventory: &mut inventory,
        };
        visitor.visit_file(file);
    })?;
    if !graph.diagnostics.is_empty() {
        for diagnostic in &graph.diagnostics {
            eprintln!("{diagnostic}");
        }
        bail!(
            "production source scan found {} error(s)",
            graph.diagnostics.len()
        );
    }

    inventory.workspace_root = graph.workspace_root;
    inventory.files_scanned = graph.files_scanned;
    inventory.sort_and_dedup();
    Ok(inventory)
}

#[derive(Default)]
struct Inventory {
    workspace_root: PathBuf,
    files_scanned: usize,
    fields: Vec<FieldRecord>,
    messages: Vec<MessageRecord>,
    unsupported: Vec<UnsupportedRecord>,
    findings: Vec<Finding>,
}

impl Inventory {
    fn sort_and_dedup(&mut self) {
        self.fields.sort();
        self.fields.dedup();
        self.messages.sort();
        self.messages.dedup();
        self.unsupported.sort();
        self.unsupported.dedup();
        self.findings.sort();
        self.findings.dedup();
    }

    fn render_json(&self) -> String {
        let mut output = String::new();
        writeln!(output, "{{").unwrap();
        writeln!(output, "  \"schema_version\": 1,").unwrap();
        writeln!(output, "  \"files_scanned\": {},", self.files_scanned).unwrap();
        let field_aggregates = self.field_aggregates();
        render_json_array(
            &mut output,
            "field_aggregates",
            &field_aggregates,
            FieldAggregate::render_json,
        );
        output.push_str(",\n");
        let message_aggregates = self.message_aggregates();
        render_json_array(
            &mut output,
            "message_aggregates",
            &message_aggregates,
            MessageAggregate::render_json,
        );
        output.push_str(",\n");
        render_json_array(&mut output, "fields", &self.fields, |record| {
            record.render_json()
        });
        output.push_str(",\n");
        render_json_array(&mut output, "messages", &self.messages, |record| {
            record.render_json()
        });
        output.push_str(",\n");
        render_json_array(&mut output, "unsupported", &self.unsupported, |record| {
            record.render_json()
        });
        output.push_str(",\n");
        render_json_array(&mut output, "findings", &self.findings, |record| {
            record.render_json()
        });
        output.push_str("\n}\n");
        output
    }

    fn render_markdown(&self) -> String {
        let mut output = String::new();
        writeln!(output, "# Structured log inventory\n").unwrap();
        writeln!(
            output,
            "{} production Rust {}, {} {}, {} {}, {} unsupported {}, {} {}.\n",
            self.files_scanned,
            plural(self.files_scanned, "file", "files"),
            self.fields.len(),
            plural(self.fields.len(), "field", "fields"),
            self.messages.len(),
            plural(self.messages.len(), "message", "messages"),
            self.unsupported.len(),
            plural(self.unsupported.len(), "site", "sites"),
            self.findings.len(),
            plural(self.findings.len(), "finding", "findings"),
        )
        .unwrap();

        output.push_str("## Fields\n\n");
        output.push_str(
            "| Source key | Rendered key | Count | Surfaces | Metric label | Formats | Known contract |\n",
        );
        output.push_str("|---|---|---:|---|---|---|---|\n");
        for field in self.field_aggregates() {
            writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} |",
                markdown(&field.source_name),
                markdown(&field.rendered_name),
                field.count,
                markdown(&join_surfaces(&field.surfaces)),
                if field.surfaces.contains(&Surface::MetricLabel) {
                    "yes"
                } else {
                    "no"
                },
                markdown(&join_formats(&field.formats)),
                markdown(&field.guidance),
            )
            .unwrap();
        }

        output.push_str("\n## Messages\n\n");
        output.push_str("| Macro | Kind | Count | Text |\n");
        output.push_str("|---|---|---:|---|\n");
        for message in self.message_aggregates() {
            writeln!(
                output,
                "| {} | {} | {} | {} |",
                markdown(&message.macro_name),
                message.kind.as_str(),
                message.count,
                markdown(message.text.as_deref().unwrap_or("")),
            )
            .unwrap();
        }

        output.push_str("\n## Findings\n\n");
        output.push_str("| Location | Surface | Rule | Subject | Enforcement |\n");
        output.push_str("|---|---|---|---|---|\n");
        for finding in &self.findings {
            writeln!(
                output,
                "| {} | {} | {} | {} | {} |",
                markdown(&finding.location.to_string()),
                finding.surface.as_str(),
                finding.rule.as_str(),
                markdown(&finding.subject),
                if finding.advisory {
                    "advisory"
                } else {
                    "baseline"
                },
            )
            .unwrap();
        }

        output.push_str("\n## Unsupported syntax\n\n");
        output.push_str("| Location | Surface | Detail |\n");
        output.push_str("|---|---|---|\n");
        for record in &self.unsupported {
            writeln!(
                output,
                "| {} | {} | {} |",
                markdown(&record.location.to_string()),
                record.surface.as_str(),
                markdown(&record.detail),
            )
            .unwrap();
        }
        output
    }

    fn field_aggregates(&self) -> Vec<FieldAggregate> {
        let mut fields =
            BTreeMap::<(String, String), (usize, BTreeSet<Surface>, BTreeSet<FieldFormat>)>::new();
        for field in &self.fields {
            let aggregate = fields
                .entry((field.source_name.clone(), field.rendered_name.clone()))
                .or_default();
            aggregate.0 += 1;
            aggregate.1.insert(field.surface);
            aggregate.2.insert(field.format);
        }

        fields
            .into_iter()
            .map(
                |((source_name, rendered_name), (count, surfaces, formats))| FieldAggregate {
                    guidance: field_guidance(&source_name, &surfaces),
                    source_name,
                    rendered_name,
                    count,
                    surfaces: surfaces.into_iter().collect(),
                    formats: formats.into_iter().collect(),
                },
            )
            .collect()
    }

    fn message_aggregates(&self) -> Vec<MessageAggregate> {
        let mut messages = BTreeMap::<(String, MessageKind, Option<String>), usize>::new();
        for message in &self.messages {
            *messages
                .entry((
                    message.macro_name.clone(),
                    message.kind,
                    message.text.clone(),
                ))
                .or_default() += 1;
        }
        messages
            .into_iter()
            .map(|((macro_name, kind, text), count)| MessageAggregate {
                macro_name,
                kind,
                text,
                count,
            })
            .collect()
    }
}

fn render_json_array<T>(
    output: &mut String,
    name: &str,
    records: &[T],
    render: impl Fn(&T) -> String,
) {
    writeln!(output, "  {}: [", json(name)).unwrap();
    for (index, record) in records.iter().enumerate() {
        write!(output, "    {}", render(record)).unwrap();
        if index + 1 != records.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("  ]");
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Surface {
    PlainTracingEvent,
    InstrumentedEventLog,
    Span,
    MetricLabel,
}

impl Surface {
    fn as_str(self) -> &'static str {
        match self {
            Self::PlainTracingEvent => "plain_tracing_event",
            Self::InstrumentedEventLog => "instrumented_event_log",
            Self::Span => "span",
            Self::MetricLabel => "metric_label",
        }
    }

    fn schema(self) -> FieldSurface {
        match self {
            Self::PlainTracingEvent => FieldSurface::PlainTracingEvent,
            Self::InstrumentedEventLog => FieldSurface::InstrumentedEventLog,
            Self::Span => FieldSurface::Span,
            Self::MetricLabel => FieldSurface::MetricLabel,
        }
    }

    fn is_gated(self) -> bool {
        matches!(
            self,
            Self::PlainTracingEvent | Self::InstrumentedEventLog | Self::Span
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FieldFormat {
    Native,
    Display,
    Debug,
    Unknown,
}

impl FieldFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Display => "display",
            Self::Debug => "debug",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FieldRecord {
    location: Location,
    surface: Surface,
    source_name: String,
    rendered_name: String,
    format: FieldFormat,
    source: String,
}

impl FieldRecord {
    fn render_json(&self) -> String {
        format!(
            "{{\"path\":{},\"line\":{},\"column\":{},\"surface\":{},\"source_name\":{},\"rendered_name\":{},\"format\":{},\"source\":{}}}",
            json_path(&self.location.path),
            self.location.line,
            self.location.column,
            json(self.surface.as_str()),
            json(&self.source_name),
            json(&self.rendered_name),
            json(self.format.as_str()),
            json(&self.source),
        )
    }
}

struct FieldAggregate {
    source_name: String,
    rendered_name: String,
    count: usize,
    surfaces: Vec<Surface>,
    formats: Vec<FieldFormat>,
    guidance: String,
}

impl FieldAggregate {
    fn render_json(&self) -> String {
        format!(
            "{{\"source_name\":{},\"rendered_name\":{},\"count\":{},\"surfaces\":[{}],\"metric_label\":{},\"formats\":[{}],\"guidance\":{}}}",
            json(&self.source_name),
            json(&self.rendered_name),
            self.count,
            self.surfaces
                .iter()
                .map(|surface| json(surface.as_str()))
                .collect::<Vec<_>>()
                .join(","),
            self.surfaces.contains(&Surface::MetricLabel),
            self.formats
                .iter()
                .map(|format| json(format.as_str()))
                .collect::<Vec<_>>()
                .join(","),
            json(&self.guidance),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MessageKind {
    Static,
    Interpolated,
    Dynamic,
    Missing,
}

impl MessageKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Interpolated => "interpolated",
            Self::Dynamic => "dynamic",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MessageRecord {
    location: Location,
    macro_name: String,
    kind: MessageKind,
    text: Option<String>,
}

impl MessageRecord {
    fn render_json(&self) -> String {
        format!(
            "{{\"path\":{},\"line\":{},\"column\":{},\"macro\":{},\"kind\":{},\"text\":{}}}",
            json_path(&self.location.path),
            self.location.line,
            self.location.column,
            json(&self.macro_name),
            json(self.kind.as_str()),
            optional_json(self.text.as_deref()),
        )
    }
}

struct MessageAggregate {
    macro_name: String,
    kind: MessageKind,
    text: Option<String>,
    count: usize,
}

impl MessageAggregate {
    fn render_json(&self) -> String {
        format!(
            "{{\"macro\":{},\"kind\":{},\"count\":{},\"text\":{}}}",
            json(&self.macro_name),
            json(self.kind.as_str()),
            self.count,
            optional_json(self.text.as_deref()),
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct UnsupportedRecord {
    location: Location,
    surface: Surface,
    detail: String,
}

impl UnsupportedRecord {
    fn render_json(&self) -> String {
        format!(
            "{{\"path\":{},\"line\":{},\"column\":{},\"surface\":{},\"detail\":{}}}",
            json_path(&self.location.path),
            self.location.line,
            self.location.column,
            json(self.surface.as_str()),
            json(&self.detail),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Rule {
    DynamicMessage,
    InterpolatedMessage,
    MissingMessage,
    InvalidFieldName,
    ReservedField,
    DiscouragedAlias,
    FieldCollision,
    UnsupportedSyntax,
}

impl Rule {
    fn as_str(self) -> &'static str {
        match self {
            Self::DynamicMessage => "dynamic_message",
            Self::InterpolatedMessage => "interpolated_message",
            Self::MissingMessage => "missing_message",
            Self::InvalidFieldName => "invalid_field_name",
            Self::ReservedField => "reserved_field",
            Self::DiscouragedAlias => "discouraged_alias",
            Self::FieldCollision => "field_collision",
            Self::UnsupportedSyntax => "unsupported_syntax",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Finding {
    location: Location,
    surface: Surface,
    rule: Rule,
    subject: String,
    detail: String,
    advisory: bool,
}

impl Finding {
    fn key(&self) -> BaselineKey {
        BaselineKey {
            path: self.location.path.clone(),
            surface: self.surface,
            rule: self.rule,
            subject: self.subject.clone(),
        }
    }

    fn render_json(&self) -> String {
        format!(
            "{{\"path\":{},\"line\":{},\"column\":{},\"surface\":{},\"rule\":{},\"subject\":{},\"detail\":{},\"enforcement\":{}}}",
            json_path(&self.location.path),
            self.location.line,
            self.location.column,
            json(self.surface.as_str()),
            json(self.rule.as_str()),
            json(&self.subject),
            json(&self.detail),
            json(if self.advisory {
                "advisory"
            } else {
                "baseline"
            }),
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Location {
    path: PathBuf,
    line: usize,
    column: usize,
}

impl Location {
    fn from_span(path: &Path, span: Span) -> Self {
        let start = span.start();
        Self {
            path: path.to_path_buf(),
            line: start.line,
            column: start.column + 1,
        }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.path.display(),
            self.line,
            self.column
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BaselineKey {
    path: PathBuf,
    surface: Surface,
    rule: Rule,
    subject: String,
}

#[derive(Debug)]
struct BaselineEntry {
    key: BaselineKey,
    count: usize,
    reason: String,
}

fn grouped_gated_findings(findings: &[Finding]) -> BTreeMap<BaselineKey, usize> {
    let mut grouped = BTreeMap::new();
    for finding in findings.iter().filter(|finding| !finding.advisory) {
        *grouped.entry(finding.key()).or_insert(0) += 1;
    }
    grouped
}

fn read_baseline(path: &Path) -> eyre::Result<Vec<BaselineEntry>> {
    let source = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read structured-log baseline {}", path.display()))?;
    let document = source
        .parse::<DocumentMut>()
        .wrap_err_with(|| format!("failed to parse structured-log baseline {}", path.display()))?;
    let schema_version = document
        .get("schema_version")
        .and_then(TomlItem::as_integer)
        .ok_or_else(|| {
            eyre::eyre!(
                "structured-log baseline {} requires integer `schema_version`",
                path.display()
            )
        })?;
    if schema_version != 1 {
        bail!(
            "structured-log baseline {} uses unsupported schema_version {schema_version}",
            path.display()
        );
    }
    let entries = document
        .get("exception")
        .and_then(TomlItem::as_array_of_tables);

    entries
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, table)| parse_baseline_entry(table, index + 1))
        .collect()
}

fn parse_baseline_entry(table: &Table, index: usize) -> eyre::Result<BaselineEntry> {
    let required_string = |name: &str| -> eyre::Result<String> {
        table
            .get(name)
            .and_then(TomlItem::as_str)
            .map(str::to_string)
            .ok_or_else(|| eyre::eyre!("exception {index} requires string `{name}`"))
    };
    let path = PathBuf::from(required_string("path")?);
    let surface = parse_surface(&required_string("surface")?)
        .ok_or_else(|| eyre::eyre!("exception {index} has an unknown surface"))?;
    let rule = parse_rule(&required_string("rule")?)
        .ok_or_else(|| eyre::eyre!("exception {index} has an unknown rule"))?;
    let subject = required_string("subject")?;
    let reason = required_string("reason")?;
    if reason.trim().is_empty() {
        bail!("exception {index} requires a non-empty reason");
    }
    let count = table
        .get("count")
        .and_then(TomlItem::as_integer)
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .ok_or_else(|| eyre::eyre!("exception {index} requires a positive integer `count`"))?;

    Ok(BaselineEntry {
        key: BaselineKey {
            path,
            surface,
            rule,
            subject,
        },
        count,
        reason,
    })
}

fn write_baseline(path: &Path, findings: &[Finding]) -> eyre::Result<()> {
    let reviewed_reasons = if path.exists() {
        read_baseline(path)?
            .into_iter()
            .map(|entry| (entry.key, entry.reason))
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    let mut exceptions = ArrayOfTables::new();
    for (key, count) in grouped_gated_findings(findings) {
        let mut table = Table::new();
        table["path"] = value(key.path.to_string_lossy().as_ref());
        table["surface"] = value(key.surface.as_str());
        table["rule"] = value(key.rule.as_str());
        table["subject"] = value(key.subject.as_str());
        table["count"] = value(i64::try_from(count).expect("finding count fits in i64"));
        table["reason"] = value(
            reviewed_reasons
                .get(&key)
                .map(String::as_str)
                .unwrap_or("TODO: explain why this exception remains."),
        );
        exceptions.push(table);
    }

    let mut document = DocumentMut::new();
    document["schema_version"] = value(1);
    if !exceptions.is_empty() {
        document["exception"] = TomlItem::ArrayOfTables(exceptions);
    }
    fs::write(path, format!("{BASELINE_HEADER}{document}"))
        .wrap_err_with(|| format!("failed to write structured-log baseline {}", path.display()))
}

fn compare_baseline(findings: &[Finding], baseline: &[BaselineEntry]) -> Vec<String> {
    let actual = grouped_gated_findings(findings);
    let mut expected = BTreeMap::<BaselineKey, usize>::new();
    let mut diagnostics = Vec::new();
    for entry in baseline {
        if expected.insert(entry.key.clone(), entry.count).is_some() {
            diagnostics.push(format!(
                "duplicate baseline entry for {} {} {} `{}`",
                entry.key.path.display(),
                entry.key.surface.as_str(),
                entry.key.rule.as_str(),
                entry.key.subject
            ));
        }
        if entry.reason.trim().is_empty() {
            diagnostics.push(format!(
                "baseline entry for {} {} {} `{}` has a blank reason",
                entry.key.path.display(),
                entry.key.surface.as_str(),
                entry.key.rule.as_str(),
                entry.key.subject
            ));
        } else if is_placeholder_reason(&entry.reason) {
            diagnostics.push(format!(
                "baseline entry for {} {} {} `{}` still has a placeholder reason",
                entry.key.path.display(),
                entry.key.surface.as_str(),
                entry.key.rule.as_str(),
                entry.key.subject
            ));
        }
    }

    let keys = actual
        .keys()
        .chain(expected.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for key in keys {
        let actual_count = actual.get(&key).copied().unwrap_or_default();
        let expected_count = expected.get(&key).copied().unwrap_or_default();
        if actual_count > expected_count {
            diagnostics.push(format!(
                "{}: new {} {} `{}` finding(s): found {actual_count}, baseline allows {expected_count}",
                key.path.display(),
                key.surface.as_str(),
                key.rule.as_str(),
                key.subject
            ));
        } else if actual_count < expected_count {
            diagnostics.push(format!(
                "{}: stale {} {} `{}` baseline: found {actual_count}, baseline allows {expected_count}",
                key.path.display(),
                key.surface.as_str(),
                key.rule.as_str(),
                key.subject
            ));
        }
    }
    diagnostics.sort();
    diagnostics
}

fn parse_surface(value: &str) -> Option<Surface> {
    match value {
        "plain_tracing_event" => Some(Surface::PlainTracingEvent),
        "instrumented_event_log" => Some(Surface::InstrumentedEventLog),
        "span" => Some(Surface::Span),
        "metric_label" => Some(Surface::MetricLabel),
        _ => None,
    }
}

fn parse_rule(value: &str) -> Option<Rule> {
    match value {
        "dynamic_message" => Some(Rule::DynamicMessage),
        "interpolated_message" => Some(Rule::InterpolatedMessage),
        "missing_message" => Some(Rule::MissingMessage),
        "invalid_field_name" => Some(Rule::InvalidFieldName),
        "reserved_field" => Some(Rule::ReservedField),
        "discouraged_alias" => Some(Rule::DiscouragedAlias),
        "field_collision" => Some(Rule::FieldCollision),
        "unsupported_syntax" => Some(Rule::UnsupportedSyntax),
        _ => None,
    }
}

fn is_placeholder_reason(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("todo") || reason.contains("placeholder") || reason.contains("explain why")
}

fn json(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                write!(output, "\\u{:04x}", u32::from(character)).unwrap();
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn json_path(path: &Path) -> String {
    json(path.to_string_lossy().as_ref())
}

fn optional_json(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), json)
}

fn markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn plural(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn join_surfaces(surfaces: &[Surface]) -> String {
    surfaces
        .iter()
        .map(|surface| surface.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_formats(formats: &[FieldFormat]) -> String {
    formats
        .iter()
        .map(|format| format.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn field_guidance(name: &str, surfaces: &BTreeSet<Surface>) -> String {
    let mut guidance = BTreeSet::new();
    if let Some(definition) = known_field_definition(name) {
        guidance.insert(format!("{:?}: {}", definition.concept, definition.summary));
    }
    for surface in surfaces {
        let usage = field_use(name, surface.schema());
        if usage != FieldUse::Unspecified || known_field_definition(name).is_some() {
            guidance.insert(format!("{}: {usage:?}.", surface.as_str()));
        }
        if let Some(alias) = field_alias(name, surface.schema()) {
            let target = match alias.target {
                AliasTarget::Field(target) => format!("`{target}`"),
                AliasTarget::Family(family) => format!("the `{family:?}` family"),
                _ => "the canonical field".to_string(),
            };
            guidance.insert(format!(
                "{:?} alias for {target}: {}",
                alias.confidence, alias.summary
            ));
        }
    }
    if let Some(family) = field_family(name) {
        guidance.insert(format!("{:?} family: {}", family.family, family.summary));
    }
    guidance.into_iter().collect::<Vec<_>>().join(" ")
}

fn known_field_definition(
    name: &str,
) -> Option<&'static carbide_observability_schema::FieldDefinition> {
    [
        FieldSurface::PlainTracingEvent,
        FieldSurface::InstrumentedEventLog,
        FieldSurface::Span,
        FieldSurface::FormatterMetadata,
        FieldSurface::MetricLabel,
    ]
    .into_iter()
    .find_map(|surface| field_definition(name, surface))
}

fn normalized_field_name<'a>(name: &'a str, surface: FieldSurface) -> Cow<'a, str> {
    match field_alias(name, surface) {
        Some(alias) if alias.confidence == AliasConfidence::Unambiguous => match alias.target {
            AliasTarget::Field(target) => Cow::Borrowed(target),
            _ => Cow::Borrowed(name),
        },
        _ => Cow::Borrowed(name),
    }
}

#[derive(Clone, Copy, Debug)]
enum MacroKind {
    LevelEvent,
    GenericEvent,
    LevelSpan,
    GenericSpan,
}

#[derive(Default)]
struct TracingImports {
    crate_aliases: BTreeSet<String>,
    macros: BTreeMap<String, MacroKind>,
}

impl TracingImports {
    fn from_items<'a>(items: impl IntoIterator<Item = &'a Item>) -> Self {
        let mut imports = Self::default();
        imports.crate_aliases.insert("tracing".to_string());
        for item in items {
            let Item::Use(item_use) = item else {
                continue;
            };
            if source_graph::cfg_is_production_possible(&item_use.attrs) {
                imports.collect_root(&item_use.tree);
            }
        }
        imports
    }

    fn from_block(block: &syn::Block) -> Self {
        Self::from_items(block.stmts.iter().filter_map(|statement| {
            let syn::Stmt::Item(item) = statement else {
                return None;
            };
            Some(item)
        }))
    }

    fn collect_root(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) if path.ident == "tracing" => {
                self.collect_tracing(&path.tree);
            }
            UseTree::Name(name) if name.ident == "tracing" => {
                self.crate_aliases.insert(name.ident.to_string());
            }
            UseTree::Rename(rename) if rename.ident == "tracing" => {
                self.crate_aliases.insert(rename.rename.to_string());
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_root(item);
                }
            }
            _ => {}
        }
    }

    fn collect_tracing(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Name(name) if name.ident == "self" => {
                self.crate_aliases.insert("tracing".to_string());
            }
            UseTree::Rename(rename) if rename.ident == "self" => {
                self.crate_aliases.insert(rename.rename.to_string());
            }
            UseTree::Name(name) => {
                if let Some(kind) = known_macro(name.ident.to_string().as_str()) {
                    self.macros.insert(name.ident.to_string(), kind);
                }
            }
            UseTree::Rename(rename) => {
                if let Some(kind) = known_macro(rename.ident.to_string().as_str()) {
                    self.macros.insert(rename.rename.to_string(), kind);
                }
            }
            UseTree::Glob(_) => {
                for name in TRACING_MACROS {
                    self.macros
                        .insert((*name).to_string(), known_macro(name).unwrap());
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_tracing(item);
                }
            }
            UseTree::Path(_) => {}
        }
    }

    fn classify(&self, path: &[String]) -> Option<MacroKind> {
        match path {
            [name] => self.macros.get(name).copied(),
            [crate_name, rest @ ..] if self.crate_aliases.contains(crate_name) => {
                rest.last().and_then(|name| known_macro(name))
            }
            _ => None,
        }
    }
}

const TRACING_MACROS: &[&str] = &[
    "trace",
    "debug",
    "info",
    "warn",
    "error",
    "event",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
    "span",
];

fn known_macro(name: &str) -> Option<MacroKind> {
    match name {
        "trace" | "debug" | "info" | "warn" | "error" => Some(MacroKind::LevelEvent),
        "event" => Some(MacroKind::GenericEvent),
        "trace_span" | "debug_span" | "info_span" | "warn_span" | "error_span" => {
            Some(MacroKind::LevelSpan)
        }
        "span" => Some(MacroKind::GenericSpan),
        _ => None,
    }
}

struct ImportScope {
    imports: TracingImports,
    module_boundary: bool,
}

struct StructuredLogVisitor<'a> {
    path: &'a Path,
    scopes: Vec<ImportScope>,
    inventory: &'a mut Inventory,
}

impl StructuredLogVisitor<'_> {
    fn classify_macro(&self, path: &[String]) -> Option<MacroKind> {
        if path.len() > 1 && path.first().is_some_and(|segment| segment == "tracing") {
            return path.last().and_then(|name| known_macro(name));
        }
        for scope in self.scopes.iter().rev() {
            if let Some(kind) = scope.imports.classify(path) {
                return Some(kind);
            }
            if scope.module_boundary {
                break;
            }
        }
        None
    }

    fn record_field(
        &mut self,
        span: Span,
        surface: Surface,
        source_name: &str,
        format: FieldFormat,
        source: impl Into<String>,
    ) {
        let source_name = source_name.to_string();
        let rendered_name = rendered_field_name(&source_name).into_owned();
        let location = Location::from_span(self.path, span);
        self.inventory.fields.push(FieldRecord {
            location: location.clone(),
            surface,
            source_name: source_name.clone(),
            rendered_name: rendered_name.clone(),
            format,
            source: source.into(),
        });

        if let Err(error) = validate_field_name(&source_name, surface.schema()) {
            self.inventory.findings.push(Finding {
                location: location.clone(),
                surface,
                rule: Rule::InvalidFieldName,
                subject: source_name.clone(),
                detail: error.to_string(),
                advisory: !surface.is_gated(),
            });
        }

        if is_reserved_field(&source_name, surface.schema()) {
            let usage = field_use(&source_name, surface.schema());
            self.inventory.findings.push(Finding {
                location: location.clone(),
                surface,
                rule: Rule::ReservedField,
                subject: source_name.clone(),
                detail: match usage {
                    FieldUse::FrameworkOwned => {
                        "The framework owns this key on this surface.".to_string()
                    }
                    FieldUse::Forbidden => "This key is forbidden on this surface.".to_string(),
                    _ => "This key is reserved on this surface.".to_string(),
                },
                advisory: !surface.is_gated(),
            });
        }

        if rendered_name != source_name
            && surface != Surface::MetricLabel
            && is_reserved_field(&rendered_name, surface.schema())
        {
            self.inventory.findings.push(Finding {
                location: location.clone(),
                surface,
                rule: Rule::FieldCollision,
                subject: rendered_name.clone(),
                detail: format!(
                    "`{source_name}` renders as framework-owned or reserved logfmt key `{rendered_name}`."
                ),
                advisory: !surface.is_gated(),
            });
        }

        if let Some(alias) = field_alias(&source_name, surface.schema())
            && alias.confidence == AliasConfidence::Unambiguous
        {
            let target = match alias.target {
                AliasTarget::Field(target) => format!("`{target}`"),
                AliasTarget::Family(family) => format!("the `{family:?}` naming family"),
                _ => "the canonical field name".to_string(),
            };
            self.inventory.findings.push(Finding {
                location,
                surface,
                rule: Rule::DiscouragedAlias,
                subject: source_name,
                detail: format!("Use {target}. {}", alias.summary),
                advisory: !surface.is_gated(),
            });
        }
    }

    fn record_message(&mut self, span: Span, macro_name: &str, message: ParsedMessage) {
        let location = Location::from_span(self.path, span);
        self.inventory.messages.push(MessageRecord {
            location: location.clone(),
            macro_name: macro_name.to_string(),
            kind: message.kind,
            text: message.text.clone(),
        });

        let rule = match message.kind {
            MessageKind::Static => return,
            MessageKind::Interpolated => Rule::InterpolatedMessage,
            MessageKind::Dynamic => Rule::DynamicMessage,
            MessageKind::Missing => Rule::MissingMessage,
        };
        self.inventory.findings.push(Finding {
            location,
            surface: Surface::PlainTracingEvent,
            rule,
            subject: message.text.unwrap_or_else(|| macro_name.to_string()),
            detail: match message.kind {
                MessageKind::Interpolated => {
                    "Use a stable literal and record dynamic values as structured fields."
                        .to_string()
                }
                MessageKind::Dynamic => {
                    "Tracing messages must be stable string literals.".to_string()
                }
                MessageKind::Missing => {
                    "Tracing events must include a stable human-readable message.".to_string()
                }
                MessageKind::Static => unreachable!(),
            },
            advisory: false,
        });
    }

    fn record_unsupported(&mut self, span: Span, surface: Surface, detail: impl Into<String>) {
        let location = Location::from_span(self.path, span);
        let detail = detail.into();
        self.inventory.unsupported.push(UnsupportedRecord {
            location: location.clone(),
            surface,
            detail: detail.clone(),
        });
        self.inventory.findings.push(Finding {
            location,
            surface,
            rule: Rule::UnsupportedSyntax,
            subject: detail.clone(),
            detail,
            advisory: !surface.is_gated(),
        });
    }

    fn record_field_collisions(&mut self, surface: Surface, fields: &[ParsedField]) {
        let mut collision_keys = BTreeMap::<String, BTreeSet<usize>>::new();
        for (index, field) in fields.iter().enumerate() {
            collision_keys
                .entry(rendered_field_name(&field.name).into_owned())
                .or_default()
                .insert(index);
            let normalized = normalized_field_name(&field.name, surface.schema());
            collision_keys
                .entry(rendered_field_name(normalized.as_ref()).into_owned())
                .or_default()
                .insert(index);
        }
        for (name, field_indexes) in collision_keys {
            if field_indexes.len() < 2 {
                continue;
            }
            for field_index in field_indexes.into_iter().skip(1) {
                self.inventory.findings.push(Finding {
                    location: Location::from_span(self.path, fields[field_index].span),
                    surface,
                    rule: Rule::FieldCollision,
                    subject: name.clone(),
                    detail:
                        "Multiple fields in this call normalize or render to the same logfmt key."
                            .to_string(),
                    advisory: !surface.is_gated(),
                });
            }
        }
    }

    fn scan_macro(&mut self, kind: MacroKind, macro_name: &str, span: Span, tokens: TokenStream) {
        let parsed = parse_tracing_macro(kind, tokens);
        let surface = match kind {
            MacroKind::LevelEvent | MacroKind::GenericEvent => Surface::PlainTracingEvent,
            MacroKind::LevelSpan | MacroKind::GenericSpan => Surface::Span,
        };
        self.record_field_collisions(surface, &parsed.fields);
        for field in parsed.fields {
            self.record_field(field.span, surface, &field.name, field.format, macro_name);
        }
        for unsupported in parsed.unsupported {
            self.record_unsupported(unsupported.span, surface, unsupported.detail);
        }
        if let Some(message) = parsed.message {
            self.record_message(span, macro_name, message);
        }
    }

    fn scan_nested_macros(&mut self, tokens: TokenStream) {
        self.scan_nested_token_slice(&tokens.into_iter().collect::<Vec<_>>());
    }

    fn scan_nested_token_slice(&mut self, tokens: &[TokenTree]) {
        let mut index = 0;
        while index < tokens.len() {
            if let Some(invocation) = macro_invocation(tokens, index) {
                let name = invocation
                    .path
                    .last()
                    .map(String::as_str)
                    .unwrap_or_default();
                if is_syntax_as_data_macro(name) {
                    index = invocation.end;
                    continue;
                }
                if let Some(kind) = self.classify_macro(&invocation.path) {
                    self.scan_macro(kind, name, invocation.span, invocation.group.stream());
                }
                self.scan_nested_macros(invocation.group.stream());
                index = invocation.end;
                continue;
            }

            if let TokenTree::Group(group) = &tokens[index] {
                self.scan_nested_macros(group.stream());
            }
            index += 1;
        }
    }

    fn scan_event_fields(&mut self, attrs: &[Attribute], fields: &syn::Fields, event_type: &str) {
        if !has_event_declaration(attrs) {
            return;
        }
        let logs = event_logs(attrs);
        for field in fields {
            if !source_graph::cfg_is_production_possible(&field.attrs) {
                continue;
            }
            let Some(ident) = &field.ident else {
                self.record_unsupported(
                    field.span(),
                    Surface::InstrumentedEventLog,
                    format!("Event `{event_type}` has an unnamed field"),
                );
                continue;
            };
            let field_name = source_ident(ident);
            if let Some(metric_name) = label_name(field) {
                if logs {
                    self.record_field(
                        ident.span(),
                        Surface::InstrumentedEventLog,
                        &field_name,
                        FieldFormat::Display,
                        event_type,
                    );
                }
                self.record_field(
                    ident.span(),
                    Surface::MetricLabel,
                    metric_name.as_deref().unwrap_or(&field_name),
                    FieldFormat::Display,
                    event_type,
                );
            } else if let Some(format) = context_format(field)
                && logs
            {
                self.record_field(
                    ident.span(),
                    Surface::InstrumentedEventLog,
                    &field_name,
                    format,
                    event_type,
                );
            }
        }
    }

    fn scan_instrumented_signature(&mut self, attrs: &[Attribute], signature: &Signature) {
        for span in production_possible_cfg_attr_instruments(attrs) {
            self.record_unsupported(
                span,
                Surface::Span,
                "production-possible #[cfg_attr(..., instrument(...))] fields and generated events are not inventoried",
            );
        }
        for attribute in attrs.iter().filter(|attribute| {
            attribute
                .path()
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "instrument")
        }) {
            let mut parsed = parse_instrument_attribute(attribute);
            let mut fields = Vec::new();
            if !parsed.skip_all {
                for argument in &signature.inputs {
                    collect_instrument_argument(argument, &mut fields);
                }
                fields.retain(|field| {
                    !parsed.skipped.contains(&field.name)
                        && !parsed.explicit_names.contains(&field.name)
                });
            }
            fields.append(&mut parsed.fields);

            self.record_field_collisions(Surface::Span, &fields);
            for field in fields {
                self.record_field(
                    field.span,
                    Surface::Span,
                    &field.name,
                    field.format,
                    "#[instrument]",
                );
            }
            for unsupported in parsed.unsupported {
                self.record_unsupported(unsupported.span, Surface::Span, unsupported.detail);
            }
            for field in parsed.generated_event_fields {
                self.record_field(
                    field.span,
                    Surface::PlainTracingEvent,
                    &field.name,
                    field.format,
                    "#[instrument(ret/err)]",
                );
            }
        }
    }
}

impl<'ast> Visit<'ast> for StructuredLogVisitor<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.scopes.push(ImportScope {
            imports: TracingImports::from_items(&file.items),
            module_boundary: true,
        });
        syn::visit::visit_file(self, file);
        self.scopes.pop();
    }

    fn visit_item(&mut self, item: &'ast Item) {
        let attrs = item_attrs(item);
        if !source_graph::cfg_is_production_possible(attrs)
            || matches!(item, Item::Fn(item) if source_graph::is_test_or_bench(&item.attrs))
        {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        for attribute in &item.attrs {
            self.visit_attribute(attribute);
        }
        let Some((_, items)) = &item.content else {
            return;
        };
        self.scopes.push(ImportScope {
            imports: TracingImports::from_items(items),
            module_boundary: true,
        });
        for item in items {
            self.visit_item(item);
        }
        self.scopes.pop();
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.scopes.push(ImportScope {
            imports: TracingImports::from_block(block),
            module_boundary: false,
        });
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.scan_event_fields(&item.attrs, &item.fields, &item.ident.to_string());
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if has_event_declaration(&item.attrs) {
            for variant in &item.variants {
                if !source_graph::cfg_is_production_possible(&variant.attrs) {
                    continue;
                }
                self.scan_event_fields(
                    &item.attrs,
                    &variant.fields,
                    &format!("{}::{}", item.ident, variant.ident),
                );
            }
        }
        syn::visit::visit_item_enum(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        let fields = syn::Fields::Named(item.fields.clone());
        self.scan_event_fields(&item.attrs, &fields, &item.ident.to_string());
        syn::visit::visit_item_union(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.scan_instrumented_signature(&item.attrs, &item.sig);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.scan_instrumented_signature(&item.attrs, &item.sig);
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.scan_instrumented_signature(&item.attrs, &item.sig);
        syn::visit::visit_trait_item_fn(self, item);
    }

    fn visit_macro(&mut self, item_macro: &'ast syn::Macro) {
        let path = item_macro
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let name = path.last().map(String::as_str).unwrap_or_default();
        if is_syntax_as_data_macro(name) {
            return;
        }
        if let Some(kind) = self.classify_macro(&path) {
            self.scan_macro(
                kind,
                name,
                item_macro.path.span(),
                item_macro.tokens.clone(),
            );
        }
        self.scan_nested_macros(item_macro.tokens.clone());
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = source_graph::impl_item_attrs(item);
        if source_graph::cfg_is_production_possible(attrs)
            && !matches!(item, syn::ImplItem::Fn(item) if source_graph::is_test_or_bench(&item.attrs))
        {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = source_graph::trait_item_attrs(item);
        if source_graph::cfg_is_production_possible(attrs)
            && !matches!(item, syn::TraitItem::Fn(item) if source_graph::is_test_or_bench(&item.attrs))
        {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if source_graph::cfg_is_production_possible(&local.attrs) {
            syn::visit::visit_local(self, local);
        }
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        if source_graph::cfg_is_production_possible(source_graph::expr_attrs(expression)) {
            syn::visit::visit_expr(self, expression);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if source_graph::cfg_is_production_possible(&arm.attrs) {
            syn::visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if source_graph::cfg_is_production_possible(&field.attrs) {
            syn::visit::visit_field_value(self, field);
        }
    }

    fn visit_pat(&mut self, pattern: &'ast syn::Pat) {
        if source_graph::cfg_is_production_possible(source_graph::pat_attrs(pattern)) {
            syn::visit::visit_pat(self, pattern);
        }
    }

    fn visit_field_pat(&mut self, field: &'ast syn::FieldPat) {
        if source_graph::cfg_is_production_possible(&field.attrs) {
            syn::visit::visit_field_pat(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if source_graph::cfg_is_production_possible(&variant.attrs) {
            syn::visit::visit_variant(self, variant);
        }
    }

    fn visit_field(&mut self, field: &'ast Field) {
        if source_graph::cfg_is_production_possible(&field.attrs) {
            syn::visit::visit_field(self, field);
        }
    }

    fn visit_generic_param(&mut self, parameter: &'ast syn::GenericParam) {
        if source_graph::cfg_is_production_possible(source_graph::generic_param_attrs(parameter)) {
            syn::visit::visit_generic_param(self, parameter);
        }
    }

    fn visit_fn_arg(&mut self, argument: &'ast syn::FnArg) {
        if source_graph::cfg_is_production_possible(source_graph::fn_arg_attrs(argument)) {
            syn::visit::visit_fn_arg(self, argument);
        }
    }

    fn visit_variadic(&mut self, variadic: &'ast syn::Variadic) {
        if source_graph::cfg_is_production_possible(&variadic.attrs) {
            syn::visit::visit_variadic(self, variadic);
        }
    }

    fn visit_bare_fn_arg(&mut self, argument: &'ast syn::BareFnArg) {
        if source_graph::cfg_is_production_possible(&argument.attrs) {
            syn::visit::visit_bare_fn_arg(self, argument);
        }
    }
}

struct ParsedMacro {
    fields: Vec<ParsedField>,
    message: Option<ParsedMessage>,
    unsupported: Vec<ParsedUnsupported>,
}

struct ParsedField {
    name: String,
    format: FieldFormat,
    span: Span,
}

struct ParsedMessage {
    kind: MessageKind,
    text: Option<String>,
}

struct ParsedUnsupported {
    span: Span,
    detail: String,
}

#[derive(Default)]
struct ParsedInstrument {
    skip_all: bool,
    skipped: BTreeSet<String>,
    explicit_names: BTreeSet<String>,
    fields: Vec<ParsedField>,
    unsupported: Vec<ParsedUnsupported>,
    generated_event_fields: Vec<ParsedField>,
}

fn parse_instrument_attribute(attribute: &Attribute) -> ParsedInstrument {
    let mut parsed = ParsedInstrument::default();
    let Meta::List(list) = &attribute.meta else {
        if matches!(&attribute.meta, Meta::NameValue(_)) {
            parsed.unsupported.push(ParsedUnsupported {
                span: attribute.span(),
                detail: "#[instrument] must use a parenthesized argument list".to_string(),
            });
        }
        return parsed;
    };

    for segment in split_commas(list.tokens.clone()) {
        match segment.as_slice() {
            [TokenTree::Ident(name)] if name == "skip_all" => {
                parsed.skip_all = true;
            }
            [TokenTree::Ident(name), TokenTree::Group(arguments)] if name == "skip" => {
                if arguments.delimiter() != Delimiter::Parenthesis {
                    parsed.unsupported.push(ParsedUnsupported {
                        span: name.span(),
                        detail: "#[instrument] skip must use parentheses".to_string(),
                    });
                    continue;
                }
                for argument in split_commas(arguments.stream()) {
                    let [TokenTree::Ident(name)] = argument.as_slice() else {
                        parsed.unsupported.push(ParsedUnsupported {
                            span: argument
                                .first()
                                .map_or_else(|| arguments.span(), TokenTree::span),
                            detail: "#[instrument] skip arguments must be parameter identifiers"
                                .to_string(),
                        });
                        continue;
                    };
                    parsed.skipped.insert(source_ident(name));
                }
            }
            [TokenTree::Ident(name), TokenTree::Group(fields)] if name == "fields" => {
                if fields.delimiter() != Delimiter::Parenthesis {
                    parsed.unsupported.push(ParsedUnsupported {
                        span: name.span(),
                        detail: "#[instrument] fields must use parentheses".to_string(),
                    });
                    continue;
                }
                for field_tokens in split_commas(fields.stream()) {
                    let explicit_name = simple_instrument_field_name(&field_tokens);
                    match parse_field(&field_tokens) {
                        Ok(field) => {
                            if let Some(name) = explicit_name {
                                parsed.explicit_names.insert(name);
                            }
                            parsed.fields.push(field);
                        }
                        Err(unsupported) => parsed.unsupported.push(unsupported),
                    }
                }
            }
            segment
                if matches!(
                    segment.first(),
                    Some(TokenTree::Ident(name)) if name == "ret" || name == "err"
                ) =>
            {
                let Some(TokenTree::Ident(name)) = segment.first() else {
                    unreachable!();
                };
                let default_format = if name == "err" {
                    FieldFormat::Display
                } else {
                    FieldFormat::Debug
                };
                let format = segment
                    .get(1)
                    .and_then(|token| match token {
                        TokenTree::Group(arguments) => {
                            arguments
                                .stream()
                                .into_iter()
                                .find_map(|token| match token {
                                    TokenTree::Ident(format) if format == "Display" => {
                                        Some(FieldFormat::Display)
                                    }
                                    TokenTree::Ident(format) if format == "Debug" => {
                                        Some(FieldFormat::Debug)
                                    }
                                    _ => None,
                                })
                        }
                        _ => None,
                    })
                    .unwrap_or(default_format);
                parsed.generated_event_fields.push(ParsedField {
                    name: if name == "err" { "error" } else { "return" }.to_string(),
                    format,
                    span: name.span(),
                });
            }
            _ => {}
        }
    }
    parsed
}

fn simple_instrument_field_name(tokens: &[TokenTree]) -> Option<String> {
    let equals = tokens.iter().position(
        |token| matches!(token, TokenTree::Punct(punctuation) if punctuation.as_char() == '='),
    );
    let name_tokens = equals.map_or(tokens, |index| &tokens[..index]);
    let (name_tokens, _) = strip_format_prefix(name_tokens);
    let [TokenTree::Ident(name)] = name_tokens else {
        return None;
    };
    Some(source_ident(name))
}

fn source_ident(ident: &proc_macro2::Ident) -> String {
    let ident = ident.to_string();
    ident.strip_prefix("r#").unwrap_or(&ident).to_string()
}

fn collect_instrument_argument(argument: &FnArg, fields: &mut Vec<ParsedField>) {
    if !source_graph::cfg_is_production_possible(source_graph::fn_arg_attrs(argument)) {
        return;
    }

    match argument {
        FnArg::Receiver(receiver) => fields.push(ParsedField {
            name: "self".to_string(),
            format: FieldFormat::Debug,
            span: receiver.self_token.span,
        }),
        FnArg::Typed(argument) => collect_instrument_pattern(
            &argument.pat,
            instrument_argument_format(&argument.ty),
            fields,
        ),
    }
}

fn collect_instrument_pattern(pattern: &Pat, format: FieldFormat, fields: &mut Vec<ParsedField>) {
    if !source_graph::cfg_is_production_possible(source_graph::pat_attrs(pattern)) {
        return;
    }

    match pattern {
        Pat::Ident(pattern) => fields.push(ParsedField {
            name: source_ident(&pattern.ident),
            format,
            span: pattern.ident.span(),
        }),
        Pat::Reference(pattern) => {
            collect_instrument_pattern(&pattern.pat, format, fields);
        }
        Pat::Struct(pattern) => {
            for field in &pattern.fields {
                if source_graph::cfg_is_production_possible(&field.attrs) {
                    collect_instrument_pattern(&field.pat, FieldFormat::Debug, fields);
                }
            }
        }
        Pat::Tuple(pattern) => {
            for element in &pattern.elems {
                collect_instrument_pattern(element, FieldFormat::Debug, fields);
            }
        }
        Pat::TupleStruct(pattern) => {
            for element in &pattern.elems {
                collect_instrument_pattern(element, FieldFormat::Debug, fields);
            }
        }
        _ => {}
    }
}

fn instrument_argument_format(argument_type: &Type) -> FieldFormat {
    const VALUE_TYPES: &[&str] = &[
        "bool",
        "str",
        "u8",
        "i8",
        "u16",
        "i16",
        "u32",
        "i32",
        "u64",
        "i64",
        "u128",
        "i128",
        "f32",
        "f64",
        "usize",
        "isize",
        "String",
        "NonZeroU8",
        "NonZeroI8",
        "NonZeroU16",
        "NonZeroI16",
        "NonZeroU32",
        "NonZeroI32",
        "NonZeroU64",
        "NonZeroI64",
        "NonZeroU128",
        "NonZeroI128",
        "NonZeroUsize",
        "NonZeroIsize",
        "Wrapping",
    ];

    match argument_type {
        Type::Path(argument_type)
            if argument_type.path.segments.last().is_some_and(|segment| {
                VALUE_TYPES.contains(&segment.ident.to_string().as_str())
            }) =>
        {
            FieldFormat::Native
        }
        Type::Reference(argument_type) => instrument_argument_format(&argument_type.elem),
        _ => FieldFormat::Debug,
    }
}

fn parse_tracing_macro(kind: MacroKind, tokens: TokenStream) -> ParsedMacro {
    let mut segments = split_commas(tokens);
    let mut required_unsupported = Vec::new();
    while segments
        .first()
        .is_some_and(|segment| is_metadata_prefix(segment))
    {
        let metadata = segments.remove(0);
        if has_forwarded_syntax(&metadata) {
            required_unsupported.push(ParsedUnsupported {
                span: metadata
                    .first()
                    .map_or_else(Span::call_site, TokenTree::span),
                detail: format!(
                    "could not resolve tracing metadata from `{}`",
                    tokens_text(&metadata)
                ),
            });
        }
    }

    let mut parsed = match kind {
        MacroKind::LevelEvent => parse_event_segments(segments),
        MacroKind::GenericEvent => {
            if !segments.is_empty() {
                let level = segments.remove(0);
                if has_forwarded_syntax(&level) {
                    required_unsupported.push(ParsedUnsupported {
                        span: level.first().map_or_else(Span::call_site, TokenTree::span),
                        detail: format!(
                            "could not resolve required event level from `{}`",
                            tokens_text(&level)
                        ),
                    });
                }
            }
            parse_event_segments(segments)
        }
        MacroKind::LevelSpan => parse_level_span_segments(segments),
        MacroKind::GenericSpan => parse_generic_span_segments(segments),
    };
    required_unsupported.append(&mut parsed.unsupported);
    parsed.unsupported = required_unsupported;
    parsed
}

fn parse_event_segments(mut segments: Vec<Vec<TokenTree>>) -> ParsedMacro {
    let mut fields = Vec::new();
    let mut unsupported = Vec::new();
    if let Some([TokenTree::Group(group)]) = segments.first().map(Vec::as_slice)
        && group.delimiter() == Delimiter::Brace
    {
        for field_tokens in split_commas(group.stream()) {
            match parse_field(&field_tokens) {
                Ok(field) => fields.push(field),
                Err(error) => unsupported.push(error),
            }
        }
        segments.remove(0);
    }

    let message_candidate = segments
        .iter()
        .enumerate()
        .find_map(|(index, segment)| static_message(segment).map(|message| (index, message)));
    if let Some((message_index, message)) = message_candidate {
        for field_tokens in &segments[..message_index] {
            match parse_field(field_tokens) {
                Ok(field) => fields.push(field),
                Err(error) => unsupported.push(error),
            }
        }
        let message_text = match message {
            Ok(message) => message,
            Err(error) => {
                unsupported.push(error);
                return ParsedMacro {
                    fields,
                    message: None,
                    unsupported,
                };
            }
        };
        let has_arguments = message_index + 1 < segments.len();
        let kind = if has_arguments || has_format_placeholder(&message_text) {
            MessageKind::Interpolated
        } else {
            MessageKind::Static
        };
        return ParsedMacro {
            fields,
            message: Some(ParsedMessage {
                kind,
                text: Some(message_text),
            }),
            unsupported,
        };
    }

    let mut dynamic_message = None;
    let mut forwarded_syntax = false;
    for segment in &segments {
        match parse_field(segment) {
            Ok(field) => fields.push(field),
            Err(error) => {
                if has_forwarded_syntax(segment) {
                    forwarded_syntax = true;
                } else {
                    dynamic_message.get_or_insert_with(|| tokens_text(segment));
                }
                unsupported.push(error);
            }
        }
    }
    let message = if let Some(message) = dynamic_message {
        Some(ParsedMessage {
            kind: MessageKind::Dynamic,
            text: Some(message),
        })
    } else if forwarded_syntax {
        None
    } else {
        Some(ParsedMessage {
            kind: MessageKind::Missing,
            text: None,
        })
    };
    ParsedMacro {
        fields,
        message,
        unsupported,
    }
}

fn parse_span_segments(segments: Vec<Vec<TokenTree>>) -> ParsedMacro {
    let mut fields = Vec::new();
    let mut unsupported = Vec::new();
    for field_tokens in segments {
        match parse_field(&field_tokens) {
            Ok(field) => fields.push(field),
            Err(error) => unsupported.push(error),
        }
    }
    ParsedMacro {
        fields,
        message: None,
        unsupported,
    }
}

fn parse_level_span_segments(mut segments: Vec<Vec<TokenTree>>) -> ParsedMacro {
    let mut required_unsupported: Vec<_> =
        take_static_span_name(&mut segments).into_iter().collect();
    let mut parsed = parse_span_segments(segments);
    required_unsupported.append(&mut parsed.unsupported);
    parsed.unsupported = required_unsupported;
    parsed
}

fn production_possible_cfg_attr_instruments(attrs: &[Attribute]) -> Vec<Span> {
    let mut spans = Vec::new();
    for attribute in attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg_attr"))
    {
        let Ok(parts) = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            continue;
        };
        spans.extend(production_possible_cfg_attr_instrument_parts(&parts));
    }
    spans
}

fn production_possible_cfg_attr_instrument_parts(parts: &Punctuated<Meta, Token![,]>) -> Vec<Span> {
    let mut parts = parts.iter();
    let Some(condition) = parts.next() else {
        return Vec::new();
    };
    let condition = condition.clone();
    let cfg_attribute: Attribute = syn::parse_quote!(#[cfg(#condition)]);
    if !source_graph::cfg_is_production_possible(std::slice::from_ref(&cfg_attribute)) {
        return Vec::new();
    }

    let mut spans = Vec::new();
    for meta in parts {
        if meta
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "instrument")
        {
            spans.push(meta.span());
        }
        if let Meta::List(list) = meta
            && list.path.is_ident("cfg_attr")
            && let Ok(nested) =
                Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
        {
            spans.extend(production_possible_cfg_attr_instrument_parts(&nested));
        }
    }
    spans
}

fn parse_generic_span_segments(mut segments: Vec<Vec<TokenTree>>) -> ParsedMacro {
    let mut required_unsupported = Vec::new();
    if !segments.is_empty() {
        let level = segments.remove(0);
        if has_forwarded_syntax(&level) {
            required_unsupported.push(ParsedUnsupported {
                span: level.first().map_or_else(Span::call_site, TokenTree::span),
                detail: format!(
                    "could not resolve required span level from `{}`",
                    tokens_text(&level)
                ),
            });
        }
    }
    required_unsupported.extend(take_static_span_name(&mut segments));

    let mut parsed = parse_span_segments(segments);
    required_unsupported.append(&mut parsed.unsupported);
    parsed.unsupported = required_unsupported;
    parsed
}

fn take_static_span_name(segments: &mut Vec<Vec<TokenTree>>) -> Option<ParsedUnsupported> {
    if segments.is_empty() {
        return None;
    }
    let name = segments.remove(0);
    match static_message(&name) {
        Some(Ok(_)) => None,
        Some(Err(error)) => Some(ParsedUnsupported {
            span: error.span,
            detail: "span names using concat! require only string literal arguments".to_string(),
        }),
        None => Some(ParsedUnsupported {
            span: name.first().map_or_else(Span::call_site, TokenTree::span),
            detail: format!(
                "could not resolve static span name from `{}`",
                tokens_text(&name)
            ),
        }),
    }
}

fn parse_field(tokens: &[TokenTree]) -> Result<ParsedField, ParsedUnsupported> {
    let Some(first) = tokens.first() else {
        return Err(ParsedUnsupported {
            span: Span::call_site(),
            detail: "empty field expression".to_string(),
        });
    };
    let span = first.span();
    let equals = tokens.iter().position(
        |token| matches!(token, TokenTree::Punct(punctuation) if punctuation.as_char() == '='),
    );
    let (name_tokens, value_tokens) = equals.map_or((tokens, &[][..]), |index| {
        (&tokens[..index], &tokens[index + 1..])
    });

    let (name_tokens, prefix_format) = strip_format_prefix(name_tokens);
    let name = parse_field_name(name_tokens).ok_or_else(|| ParsedUnsupported {
        span,
        detail: format!(
            "could not resolve static field name from `{}`",
            tokens_text(name_tokens)
        ),
    })?;
    let value_format = strip_format_prefix(value_tokens).1;

    Ok(ParsedField {
        name,
        format: value_format
            .or(prefix_format)
            .unwrap_or(FieldFormat::Native),
        span,
    })
}

fn strip_format_prefix(tokens: &[TokenTree]) -> (&[TokenTree], Option<FieldFormat>) {
    match tokens.first() {
        Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == '%' => {
            (&tokens[1..], Some(FieldFormat::Display))
        }
        Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == '?' => {
            (&tokens[1..], Some(FieldFormat::Debug))
        }
        _ => (tokens, None),
    }
}

fn parse_field_name(tokens: &[TokenTree]) -> Option<String> {
    if let [TokenTree::Literal(literal)] = tokens {
        return syn::parse_str::<syn::LitStr>(&literal.to_string())
            .ok()
            .map(|literal| literal.value());
    }
    if matches!(tokens, [TokenTree::Group(group)] if group.delimiter() == Delimiter::Brace) {
        return None;
    }

    let mut name = String::new();
    let mut expect_ident = true;
    for token in tokens {
        match token {
            TokenTree::Ident(ident) if expect_ident => {
                let ident = ident.to_string();
                name.push_str(ident.strip_prefix("r#").unwrap_or(&ident));
                expect_ident = false;
            }
            TokenTree::Punct(punctuation) if !expect_ident && punctuation.as_char() == '.' => {
                name.push('.');
                expect_ident = true;
            }
            _ => return None,
        }
    }
    (!name.is_empty() && !expect_ident).then_some(name)
}

fn literal_message(tokens: &[TokenTree]) -> Option<String> {
    let [TokenTree::Literal(literal)] = tokens else {
        return None;
    };
    syn::parse_str::<syn::LitStr>(&literal.to_string())
        .ok()
        .map(|literal| literal.value())
}

fn static_message(tokens: &[TokenTree]) -> Option<Result<String, ParsedUnsupported>> {
    if let Some(message) = literal_message(tokens) {
        return Some(Ok(message));
    }
    let invocation = macro_invocation(tokens, 0)?;
    if invocation.end != tokens.len() || invocation.path.as_slice() != ["concat"] {
        return None;
    }

    let mut message = String::new();
    for part in split_commas(invocation.group.stream()) {
        let Some(literal) = literal_message(&part) else {
            return Some(Err(ParsedUnsupported {
                span: invocation.span,
                detail:
                    "concat! messages are inventoried only when every argument is a string literal"
                        .to_string(),
            }));
        };
        message.push_str(&literal);
    }
    Some(Ok(message))
}

fn has_format_placeholder(message: &str) -> bool {
    let mut characters = message.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '{' if characters.peek() == Some(&'{') => {
                characters.next();
            }
            '}' if characters.peek() == Some(&'}') => {
                characters.next();
            }
            '{' | '}' => return true,
            _ => {}
        }
    }
    false
}

fn is_metadata_prefix(tokens: &[TokenTree]) -> bool {
    matches!(
        tokens,
        [TokenTree::Ident(name), TokenTree::Punct(colon), ..]
            if colon.as_char() == ':'
                && matches!(name.to_string().as_str(), "target" | "parent" | "name")
    )
}

fn split_commas(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut parts = vec![Vec::new()];
    for token in tokens {
        if matches!(&token, TokenTree::Punct(punctuation) if punctuation.as_char() == ',') {
            if !parts.last().is_some_and(Vec::is_empty) {
                parts.push(Vec::new());
            }
        } else {
            parts.last_mut().unwrap().push(token);
        }
    }
    if parts.last().is_some_and(Vec::is_empty) {
        parts.pop();
    }
    parts
}

fn tokens_text(tokens: &[TokenTree]) -> String {
    tokens.iter().cloned().collect::<TokenStream>().to_string()
}

fn has_forwarded_syntax(tokens: &[TokenTree]) -> bool {
    tokens.iter().any(|token| {
        matches!(token, TokenTree::Punct(punctuation) if punctuation.as_char() == '$')
            || matches!(token, TokenTree::Group(group) if has_forwarded_syntax(&group.stream().into_iter().collect::<Vec<_>>()))
    })
}

struct MacroInvocation {
    path: Vec<String>,
    span: Span,
    group: Group,
    end: usize,
}

fn macro_invocation(tokens: &[TokenTree], start: usize) -> Option<MacroInvocation> {
    let (first, mut index, span) = match tokens.get(start)? {
        TokenTree::Ident(first) => (first, start + 1, first.span()),
        TokenTree::Punct(first_colon)
            if first_colon.as_char() == ':'
                && matches!(
                    tokens.get(start + 1),
                    Some(TokenTree::Punct(second_colon)) if second_colon.as_char() == ':'
                ) =>
        {
            let TokenTree::Ident(first) = tokens.get(start + 2)? else {
                return None;
            };
            (first, start + 3, first_colon.span())
        }
        _ => return None,
    };
    let mut path = vec![first.to_string()];
    while matches!(
        (tokens.get(index), tokens.get(index + 1), tokens.get(index + 2)),
        (
            Some(TokenTree::Punct(first_colon)),
            Some(TokenTree::Punct(second_colon)),
            Some(TokenTree::Ident(_))
        ) if first_colon.as_char() == ':' && second_colon.as_char() == ':'
    ) {
        let TokenTree::Ident(segment) = &tokens[index + 2] else {
            unreachable!();
        };
        path.push(segment.to_string());
        index += 3;
    }

    let Some(TokenTree::Punct(bang)) = tokens.get(index) else {
        return None;
    };
    if bang.as_char() != '!' {
        return None;
    }
    let Some(TokenTree::Group(group)) = tokens.get(index + 1) else {
        return None;
    };
    Some(MacroInvocation {
        path,
        span,
        group: group.clone(),
        end: index + 2,
    })
}

fn is_syntax_as_data_macro(name: &str) -> bool {
    matches!(name, "quote" | "quote_spanned" | "stringify")
}

fn has_event_declaration(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("event"))
        && (attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("derive"))
            || source_graph::production_possible_cfg_attr_attribute(attrs, "derive").is_some())
}

fn event_logs(attrs: &[Attribute]) -> bool {
    for attribute in attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("event"))
    {
        let Ok(arguments) =
            attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            continue;
        };
        for argument in arguments {
            let Meta::NameValue(name_value) = argument else {
                continue;
            };
            if !name_value.path.is_ident("log") {
                continue;
            }
            if matches!(
                name_value.value,
                Expr::Path(expression)
                    if expression.path.segments.last().is_some_and(|segment| segment.ident == "off")
            ) {
                return false;
            }
        }
    }
    true
}

fn label_name(field: &Field) -> Option<Option<String>> {
    let attribute = field
        .attrs
        .iter()
        .find(|attribute| attribute.path().is_ident("label"))?;
    let Meta::List(list) = &attribute.meta else {
        return Some(None);
    };
    let arguments = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()?;
    for argument in arguments {
        let Meta::NameValue(name_value) = argument else {
            continue;
        };
        if !name_value.path.is_ident("name") {
            continue;
        }
        let Expr::Lit(expression) = name_value.value else {
            return Some(None);
        };
        let Lit::Str(name) = expression.lit else {
            return Some(None);
        };
        return Some(Some(name.value()));
    }
    Some(None)
}

fn context_format(field: &Field) -> Option<FieldFormat> {
    let attribute = field
        .attrs
        .iter()
        .find(|attribute| attribute.path().is_ident("context"))?;
    match &attribute.meta {
        Meta::Path(_) => Some(FieldFormat::Display),
        Meta::List(list) if list.tokens.to_string() == "value" => Some(FieldFormat::Native),
        Meta::List(_) | Meta::NameValue(_) => Some(FieldFormat::Unknown),
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_source(source: &str) -> Inventory {
        let file = syn::parse_file(source).expect("parse fixture source");
        let mut inventory = Inventory {
            files_scanned: 1,
            ..Inventory::default()
        };
        let mut visitor = StructuredLogVisitor {
            path: Path::new("fixture.rs"),
            scopes: Vec::new(),
            inventory: &mut inventory,
        };
        visitor.visit_file(&file);
        inventory.sort_and_dedup();
        inventory
    }

    #[test]
    fn keeps_source_and_rendered_names_separate() {
        let inventory = collect_source(
            r#"
            fn log(url: &str, flat: &str, kind: &str) {
                tracing::info!(
                    "http.url" = %url,
                    http_url = %flat,
                    r#type = %kind,
                    "request received",
                );
            }
            "#,
        );

        let names = inventory
            .fields
            .iter()
            .map(|field| (field.source_name.as_str(), field.rendered_name.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("http.url", "http_url"),
                ("http_url", "http_url"),
                ("type", "type"),
            ]
        );
        assert!(inventory.findings.iter().any(|finding| {
            finding.rule == Rule::FieldCollision && finding.subject == "http_url"
        }));
    }

    #[test]
    fn detects_rendered_collisions_with_framework_owned_keys() {
        let inventory = collect_source(
            r#"
            fn log(span_id: &str) {
                tracing::info!("span.id" = %span_id, "request received");
            }
            "#,
        );

        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::PlainTracingEvent
                && finding.rule == Rule::FieldCollision
                && finding.subject == "span_id"
                && finding
                    .detail
                    .contains("renders as framework-owned or reserved")
                && !finding.advisory
        }));
    }

    #[test]
    fn reports_each_field_after_the_first_same_call_collision() {
        let inventory = collect_source(
            r#"
            fn log(first: &str, second: &str, third: &str) {
                tracing::info!(
                    "http.url" = %first,
                    http_url = %second,
                    "http.url" = %third,
                    "request received",
                );
            }
            "#,
        );

        let collisions = inventory
            .findings
            .iter()
            .filter(|finding| {
                finding.surface == Surface::PlainTracingEvent
                    && finding.rule == Rule::FieldCollision
                    && finding.subject == "http_url"
            })
            .collect::<Vec<_>>();
        assert_eq!(collisions.len(), 2);
        assert!(collisions.iter().all(|finding| !finding.advisory));
    }

    #[test]
    fn keeps_bare_macro_imports_inside_their_module_scope() {
        let inventory = collect_source(
            r#"
            mod imported {
                use tracing::info;

                fn log() {
                    info!("recognized");
                }
            }

            mod sibling {
                fn unrelated() {
                    info!("not a tracing import in this module");
                }
            }

            #[cfg(test)]
            mod tests {
                use tracing::warn;
            }

            fn production() {
                warn!("test-only import must not leak");
            }
            "#,
        );

        assert_eq!(inventory.messages.len(), 1);
        assert_eq!(inventory.messages[0].text.as_deref(), Some("recognized"));
    }

    #[test]
    fn detects_alias_and_instrument_field_collisions() {
        let inventory = collect_source(
            r#"
            fn log(first: &str, second: &str) {
                tracing::warn!(err = %first, error = %second, "failed");
            }

            #[tracing::instrument(fields("http.url" = %first, http_url = %second))]
            fn request(first: &str, second: &str) {}
            "#,
        );

        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::PlainTracingEvent
                && finding.rule == Rule::FieldCollision
                && finding.subject == "error"
                && !finding.advisory
        }));
        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::Span
                && finding.rule == Rule::FieldCollision
                && finding.subject == "http_url"
                && !finding.advisory
        }));
    }

    #[test]
    fn instrument_arguments_follow_tracing_attribute_semantics() {
        let inventory = collect_source(
            r#"
            #[derive(Debug)]
            struct Handler;
            #[derive(Debug)]
            struct Action;
            struct Secret;

            impl Handler {
                #[tracing::instrument(
                    skip(self, secret),
                    fields(action = %action, http.url = %url)
                )]
                fn handle(
                    &self,
                    count: u64,
                    action: Action,
                    secret: Secret,
                    url: &str,
                    http_url: &str,
                    r#type: &str,
                ) {}

                #[tracing::instrument(skip_all, fields(stage = "ready"))]
                fn skipped(&self, message: &str) {}
            }
            "#,
        );

        let fields = inventory
            .fields
            .iter()
            .filter(|field| field.source == "#[instrument]")
            .map(|field| (field.source_name.as_str(), field.format))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            fields,
            BTreeMap::from([
                ("action", FieldFormat::Display),
                ("count", FieldFormat::Native),
                ("http.url", FieldFormat::Display),
                ("http_url", FieldFormat::Native),
                ("stage", FieldFormat::Native),
                ("type", FieldFormat::Native),
                ("url", FieldFormat::Native),
            ])
        );
        for omitted in ["self", "secret", "message"] {
            assert!(!fields.contains_key(omitted), "{omitted}");
        }
        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::Span
                && finding.rule == Rule::FieldCollision
                && finding.subject == "http_url"
                && !finding.advisory
        }));
    }

    #[test]
    fn instrument_patterns_and_cfgs_match_generated_fields() {
        let inventory = collect_source(
            r#"
            use tracing::instrument;

            struct Point {
                x: u8,
                y: u8,
            }
            struct Hidden;

            #[instrument(skip(hidden))]
            fn patterned(
                #[cfg(test)] test_only: u64,
                (left, right): (u64, u64),
                Point { x, y: renamed }: Point,
                [first, second]: [u8; 2],
                hidden: Hidden,
                direct: String,
            ) {}

            #[cfg(test)]
            #[instrument]
            fn test_function(message: &str) {}
            "#,
        );

        let fields = inventory
            .fields
            .iter()
            .filter(|field| field.source == "#[instrument]")
            .map(|field| (field.source_name.as_str(), field.format))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            fields,
            BTreeMap::from([
                ("direct", FieldFormat::Native),
                ("left", FieldFormat::Debug),
                ("renamed", FieldFormat::Debug),
                ("right", FieldFormat::Debug),
                ("x", FieldFormat::Debug),
            ])
        );
        for omitted in ["test_only", "first", "second", "hidden", "message"] {
            assert!(!fields.contains_key(omitted), "{omitted}");
        }
        assert!(inventory.unsupported.is_empty());
    }

    #[test]
    fn production_possible_conditional_instrumentation_requires_review() {
        let inventory = collect_source(
            r#"
            #[cfg_attr(feature = "telemetry", tracing::instrument(fields(error = %error)))]
            #[cfg_attr(target_os = "linux", tracing::instrument(skip_all))]
            fn conditionally_instrumented(error: &str) {}

            #[cfg_attr(test, tracing::instrument(fields(test_only = %test_only)))]
            fn test_only_instrumentation(test_only: &str) {}
            "#,
        );

        let unsupported = inventory
            .findings
            .iter()
            .filter(|finding| finding.rule == Rule::UnsupportedSyntax)
            .collect::<Vec<_>>();
        assert_eq!(unsupported.len(), 2);
        assert!(unsupported.iter().all(|finding| {
            finding.surface == Surface::Span
                && finding
                    .subject
                    .contains("production-possible #[cfg_attr(..., instrument(...))]")
                && !finding.advisory
        }));
        assert!(inventory.fields.is_empty());
    }

    #[test]
    fn treats_literal_concat_as_static_and_forwarded_messages_as_unsupported() {
        let inventory = collect_source(
            r#"
            const PREFIX: &str = "dynamic";

            fn log() {
                tracing::info!(concat!("stable ", "message"));
                tracing::info!(concat!(PREFIX, " message"));
            }

            macro_rules! forward {
                ($msg:expr) => {
                    tracing::info!($msg);
                };
            }
            "#,
        );

        assert!(inventory.messages.iter().any(|message| {
            message.kind == MessageKind::Static && message.text.as_deref() == Some("stable message")
        }));
        assert!(
            inventory
                .unsupported
                .iter()
                .any(|record| record.detail.contains("static field name"))
        );
        assert!(
            inventory
                .unsupported
                .iter()
                .any(|record| { record.detail.contains("every argument is a string literal") })
        );
        assert_eq!(
            inventory
                .findings
                .iter()
                .filter(|finding| finding.rule == Rule::UnsupportedSyntax)
                .count(),
            2
        );
        assert!(inventory.findings.iter().all(|finding| !finding.advisory));
        assert!(!inventory.findings.iter().any(|finding| {
            matches!(finding.rule, Rule::DynamicMessage | Rule::MissingMessage)
        }));
    }

    #[test]
    fn instruments_generated_return_events_with_their_emitted_fields() {
        let inventory = collect_source(
            r#"
            #[tracing::instrument(ret, err(Debug))]
            fn request() -> Result<u64, Error> {
                Ok(1)
            }
            "#,
        );

        let fields = inventory
            .fields
            .iter()
            .filter(|field| field.source == "#[instrument(ret/err)]")
            .map(|field| (field.source_name.as_str(), field.format))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            fields,
            BTreeMap::from([
                ("error", FieldFormat::Debug),
                ("return", FieldFormat::Debug),
            ])
        );
        assert!(inventory.unsupported.is_empty());
    }

    #[test]
    fn scans_opaque_macro_bodies_but_skips_syntax_as_data() {
        let inventory = collect_source(
            r#"
            fn log() {
                tokio::select! {
                    _ = ready() => ::tracing::warn!(attempt = 1, "retrying"),
                }
                quote::quote! {
                    tracing::error!("syntax, not a runtime log");
                };
            }
            "#,
        );

        assert_eq!(inventory.messages.len(), 1);
        assert_eq!(inventory.messages[0].text.as_deref(), Some("retrying"));
        assert_eq!(inventory.fields[0].source_name, "attempt");
    }

    #[test]
    fn span_wrappers_gate_unresolved_required_arguments() {
        let inventory = collect_source(
            r#"
            macro_rules! level_span_wrapper {
                ($($args:tt)*) => {
                    tracing::info_span!($($args)*)
                };
            }

            macro_rules! generic_span_wrapper {
                ($($args:tt)*) => {
                    tracing::span!($($args)*)
                };
            }

            fn supported(machine_id: &str) {
                tracing::info_span!("request", %machine_id);
                tracing::span!(tracing::Level::INFO, "request", %machine_id);
            }
            "#,
        );

        let unsupported = inventory
            .findings
            .iter()
            .filter(|finding| {
                finding.surface == Surface::Span && finding.rule == Rule::UnsupportedSyntax
            })
            .collect::<Vec<_>>();
        assert_eq!(unsupported.len(), 2);
        assert!(
            unsupported
                .iter()
                .all(|finding| !finding.advisory && finding.subject.contains("could not resolve"))
        );
        assert!(unsupported.iter().any(|finding| {
            finding
                .subject
                .contains("static span name from `$ ($ args) *`")
        }));
        assert!(unsupported.iter().any(|finding| {
            finding
                .subject
                .contains("required span level from `$ ($ args) *`")
        }));
        assert_eq!(
            inventory
                .fields
                .iter()
                .filter(|field| field.source_name == "machine_id")
                .count(),
            2
        );
    }

    #[test]
    fn forwarded_required_event_and_metadata_segments_are_gated() {
        let inventory = collect_source(
            r#"
            macro_rules! generic_event_wrapper {
                ($($args:tt)*) => {
                    tracing::event!($($args)*)
                };
            }

            macro_rules! span_metadata_wrapper {
                ($($args:tt)*) => {
                    tracing::info_span!(target: $($args)*)
                };
            }
            "#,
        );

        let unsupported = inventory
            .findings
            .iter()
            .filter(|finding| finding.rule == Rule::UnsupportedSyntax)
            .collect::<Vec<_>>();
        assert_eq!(unsupported.len(), 2);
        assert!(unsupported.iter().all(|finding| !finding.advisory));
        assert!(unsupported.iter().any(|finding| {
            finding
                .subject
                .contains("required event level from `$ ($ args) *`")
        }));
        assert!(unsupported.iter().any(|finding| {
            finding
                .subject
                .contains("tracing metadata from `target : $ ($ args) *`")
        }));
    }

    #[test]
    fn parses_event_and_span_metadata_prefixes() {
        let inventory = collect_source(
            r#"
            fn log(error: &str, url: &str) {
                tracing::event!(
                    target: "fixture",
                    parent: None,
                    tracing::Level::WARN,
                    { error = %error },
                    "request failed",
                );
                tracing::span!(
                    target: "fixture",
                    parent: None,
                    tracing::Level::INFO,
                    "request",
                    "http.url" = %url,
                );
            }
            "#,
        );

        assert!(inventory.fields.iter().any(|field| {
            field.surface == Surface::PlainTracingEvent
                && field.source_name == "error"
                && field.format == FieldFormat::Display
        }));
        assert!(inventory.fields.iter().any(|field| {
            field.surface == Surface::Span
                && field.source_name == "http.url"
                && field.rendered_name == "http_url"
        }));
        assert_eq!(inventory.messages.len(), 1);
        assert_eq!(inventory.messages[0].kind, MessageKind::Static);
    }

    #[test]
    fn typed_event_findings_are_gated_and_metric_labels_remain_advisory() {
        let inventory = collect_source(
            r#"
            #[derive(carbide_instrument::Event)]
            #[event(event_name = "demo", component = "test", message = "demo")]
            struct Demo {
                #[label(name = "rpc.status")]
                stage: Stage,
                #[context]
                err: Error,
                #[context]
                r#type: Kind,
            }
            "#,
        );

        assert!(inventory.fields.iter().any(|field| {
            field.surface == Surface::InstrumentedEventLog && field.source_name == "stage"
        }));
        assert!(inventory.fields.iter().any(|field| {
            field.surface == Surface::InstrumentedEventLog && field.source_name == "type"
        }));
        assert!(inventory.fields.iter().any(|field| {
            field.surface == Surface::MetricLabel && field.source_name == "rpc.status"
        }));
        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::InstrumentedEventLog
                && finding.rule == Rule::DiscouragedAlias
                && finding.subject == "err"
                && !finding.advisory
        }));
        assert!(inventory.findings.iter().any(|finding| {
            finding.surface == Surface::MetricLabel
                && finding.rule == Rule::InvalidFieldName
                && finding.subject == "rpc.status"
                && finding.advisory
        }));
    }

    #[test]
    fn typed_event_inventory_excludes_test_only_fields_and_variants() {
        let inventory = collect_source(
            r#"
            #[derive(carbide_instrument::Event)]
            #[event(event_name = "demo_struct", component = "test", message = "demo")]
            struct DemoStruct {
                #[cfg(test)]
                #[context]
                err: Error,
                #[context]
                error: Error,
            }

            #[derive(carbide_instrument::Event)]
            #[event(event_name = "demo_enum", component = "test", message = "demo")]
            enum DemoEnum {
                #[cfg(test)]
                TestOnly {
                    #[context]
                    err: Error,
                },
                Production {
                    #[cfg(test)]
                    #[context]
                    err: Error,
                    #[context]
                    error: Error,
                },
            }
            "#,
        );

        assert_eq!(
            inventory
                .fields
                .iter()
                .filter(|field| {
                    field.surface == Surface::InstrumentedEventLog && field.source_name == "error"
                })
                .count(),
            2
        );
        assert!(
            !inventory
                .fields
                .iter()
                .any(|field| { field.source.contains("TestOnly") || field.source_name == "err" })
        );
        assert!(!inventory.findings.iter().any(|finding| {
            finding.surface == Surface::InstrumentedEventLog
                && finding.rule == Rule::DiscouragedAlias
        }));
    }

    #[test]
    fn baseline_requires_reviewed_reasons_and_exact_counts() {
        let key = BaselineKey {
            path: PathBuf::from("fixture.rs"),
            surface: Surface::PlainTracingEvent,
            rule: Rule::MissingMessage,
            subject: "info".to_string(),
        };
        let finding = Finding {
            location: Location {
                path: key.path.clone(),
                line: 1,
                column: 1,
            },
            surface: key.surface,
            rule: key.rule,
            subject: key.subject.clone(),
            detail: "missing".to_string(),
            advisory: false,
        };

        let diagnostics = compare_baseline(
            &[finding],
            &[BaselineEntry {
                key,
                count: 1,
                reason: "TODO: explain why this exception remains.".to_string(),
            }],
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("placeholder reason"));
    }

    #[test]
    fn baseline_names_round_trip() {
        for surface in [
            Surface::PlainTracingEvent,
            Surface::InstrumentedEventLog,
            Surface::Span,
            Surface::MetricLabel,
        ] {
            assert_eq!(parse_surface(surface.as_str()), Some(surface));
        }
        for rule in [
            Rule::DynamicMessage,
            Rule::InterpolatedMessage,
            Rule::MissingMessage,
            Rule::InvalidFieldName,
            Rule::ReservedField,
            Rule::DiscouragedAlias,
            Rule::FieldCollision,
            Rule::UnsupportedSyntax,
        ] {
            assert_eq!(parse_rule(rule.as_str()), Some(rule));
        }
    }

    #[test]
    fn baseline_ratchet_ignores_lines_and_checks_count_in_both_directions() {
        fn finding(line: usize) -> Finding {
            Finding {
                location: Location {
                    path: PathBuf::from("fixture.rs"),
                    line,
                    column: 1,
                },
                surface: Surface::PlainTracingEvent,
                rule: Rule::MissingMessage,
                subject: "info".to_string(),
                detail: "missing".to_string(),
                advisory: false,
            }
        }
        fn baseline(count: usize) -> BaselineEntry {
            BaselineEntry {
                key: finding(1).key(),
                count,
                reason: "This legacy field-only event is migrated separately.".to_string(),
            }
        }

        assert!(compare_baseline(&[finding(200)], &[baseline(1)]).is_empty());

        let increased = compare_baseline(&[finding(200), finding(300)], &[baseline(1)]);
        assert_eq!(increased.len(), 1);
        assert!(increased[0].contains("new"));

        let stale = compare_baseline(&[], &[baseline(1)]);
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains("stale"));
    }

    #[test]
    fn json_inventory_is_valid_and_deterministic() {
        let inventory = collect_source(include_str!("../test_data/structured_logs/input.txt"));
        let first = inventory.render_json();
        assert_eq!(first, inventory.render_json());
        assert_eq!(
            first,
            include_str!("../test_data/structured_logs/inventory.json")
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&first).expect("inventory is valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["field_aggregates"].is_array());
        assert!(parsed["message_aggregates"].is_array());
    }

    #[test]
    fn fixture_inventory_matches_markdown_golden() {
        let inventory = collect_source(include_str!("../test_data/structured_logs/input.txt"));
        assert_eq!(
            inventory.render_markdown(),
            include_str!("../test_data/structured_logs/inventory.md")
        );
    }
}
