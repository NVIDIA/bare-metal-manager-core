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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use carbide_observability_schema::validate_event_name;
use eyre::bail;
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Attribute, Expr, Item, Lit, Meta, Token, UseTree};

use crate::source_graph::{
    self, cfg_is_production_possible, expr_attrs, fn_arg_attrs, generic_param_attrs,
    impl_item_attrs, is_test_or_bench, pat_attrs, production_possible_cfg_attr_attribute,
    trait_item_attrs,
};

/// Checks the direct `Event` declarations reachable from production Rust
/// library and binary targets.
///
/// Macro-expanded declarations and source pulled in through `include!` (most
/// notably `OUT_DIR` output) are intentionally outside this source check. A
/// declaration must be directly visible with `#[derive(...)]` and
/// `#[event(...)]` in the module graph; handwritten `impl Event` declarations
/// are rejected because they would bypass the identity checks. An unresolved
/// ordinary `mod` is an error. Outlined children of the known generated-source
/// directories are always skipped, whether their files are present or absent.
pub fn check() -> eyre::Result<()> {
    let report = scan_workspace()?;
    if report.diagnostics.is_empty() {
        println!(
            "Checked {} unique production Event event_name declarations",
            report.declarations.len()
        );
        return Ok(());
    }

    for diagnostic in &report.diagnostics {
        eprintln!("{diagnostic}");
    }
    bail!(
        "check-event-names found {} error(s)",
        report.diagnostics.len()
    )
}

#[derive(Debug)]
struct ScanReport {
    declarations: Vec<Declaration>,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Default)]
struct EventScope {
    direct_names: BTreeSet<String>,
    crate_aliases: BTreeSet<String>,
}

impl EventScope {
    fn from_items(items: &[Item]) -> Self {
        let mut scope = Self::default();
        for item in items {
            let Item::Use(item_use) = item else {
                continue;
            };
            if cfg_is_production_possible(&item_use.attrs) {
                scope.collect_root_import(&item_use.tree);
            }
        }
        scope
    }

    fn collect_root_import(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) if path.ident == "carbide_instrument" => {
                self.collect_instrument_import(&path.tree);
            }
            UseTree::Name(name) if name.ident == "carbide_instrument" => {
                self.crate_aliases.insert(name.ident.to_string());
            }
            UseTree::Rename(rename) if rename.ident == "carbide_instrument" => {
                self.crate_aliases.insert(rename.rename.to_string());
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_root_import(item);
                }
            }
            _ => {}
        }
    }

    fn collect_instrument_import(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Name(name) if name.ident == "Event" => {
                self.direct_names.insert(name.ident.to_string());
            }
            UseTree::Rename(rename) if rename.ident == "Event" => {
                self.direct_names.insert(rename.rename.to_string());
            }
            UseTree::Name(name) if name.ident == "self" => {
                self.crate_aliases.insert("carbide_instrument".to_string());
            }
            UseTree::Rename(rename) if rename.ident == "self" => {
                self.crate_aliases.insert(rename.rename.to_string());
            }
            UseTree::Glob(_) => {
                self.direct_names.insert("Event".to_string());
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_instrument_import(item);
                }
            }
            _ => {}
        }
    }

    fn is_event_path(&self, path: &syn::Path) -> bool {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        match segments.as_slice() {
            [name] => self.direct_names.contains(name),
            [crate_name, event]
                if event == "Event"
                    && (crate_name == "carbide_instrument"
                        || self.crate_aliases.contains(crate_name)) =>
            {
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
fn scan_roots<'a>(workspace_root: &Path, roots: impl IntoIterator<Item = &'a Path>) -> ScanReport {
    let mut scanner = Scanner::new(workspace_root);
    let graph = source_graph::scan_roots(workspace_root, roots, |_, path, file| {
        scanner.scan_file(path, file);
    });
    finish_source_graph(scanner, graph)
}

fn scan_workspace() -> eyre::Result<ScanReport> {
    let mut scanner = None::<Scanner>;
    let graph = source_graph::workspace(|workspace_root, path, file| {
        scanner
            .get_or_insert_with(|| Scanner::new(workspace_root))
            .scan_file(path, file);
    })?;
    let scanner = scanner.unwrap_or_else(|| Scanner::new(&graph.workspace_root));
    Ok(finish_source_graph(scanner, graph))
}

fn finish_source_graph(mut scanner: Scanner, graph: source_graph::SourceGraph) -> ScanReport {
    for diagnostic in graph.diagnostics {
        scanner.diagnostics.push(Diagnostic {
            location: diagnostic.location.map(|location| SourceLocation {
                path: location.path,
                line: location.line,
                column: location.column,
            }),
            message: diagnostic.message,
        });
    }
    scanner.finish()
}

struct Scanner {
    workspace_root: PathBuf,
    declarations: Vec<Declaration>,
    diagnostics: Vec<Diagnostic>,
}

impl Scanner {
    fn new(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            declarations: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn scan_file(&mut self, path: &Path, file: &syn::File) {
        self.scan_items(&file.items, path);
    }

    fn scan_items(&mut self, items: &[Item], source_path: &Path) {
        let event_scope = EventScope::from_items(items);
        for item in items {
            self.scan_item(item, source_path, &event_scope);
        }
    }

    fn scan_item(&mut self, item: &Item, source_path: &Path, event_scope: &EventScope) {
        match item {
            Item::Struct(item_struct) if cfg_is_production_possible(&item_struct.attrs) => {
                self.scan_event_declaration(&item_struct.attrs, &item_struct.ident, source_path);
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Enum(item_enum) if cfg_is_production_possible(&item_enum.attrs) => {
                self.scan_event_declaration(&item_enum.attrs, &item_enum.ident, source_path);
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Union(item_union) if cfg_is_production_possible(&item_union.attrs) => {
                self.scan_event_declaration(&item_union.attrs, &item_union.ident, source_path);
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Impl(item_impl) if cfg_is_production_possible(&item_impl.attrs) => {
                if item_impl.trait_.as_ref().is_some_and(|(_, path, _)| {
                    event_scope.is_event_path(path) || has_event_impl_signature(item_impl)
                }) {
                    let start = item_impl.impl_token.span.start();
                    self.diagnostics.push(Diagnostic::new(
                        self.location(source_path, start.line, start.column + 1),
                        "manual Event implementations are unsupported; use #[derive(Event)]"
                            .to_string(),
                    ));
                }
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Mod(item_mod) if cfg_is_production_possible(&item_mod.attrs) => {
                if let Some((_, items)) = &item_mod.content {
                    self.scan_items(items, source_path);
                }
            }
            Item::Fn(item_fn)
                if cfg_is_production_possible(&item_fn.attrs)
                    && !is_test_or_bench(&item_fn.attrs) =>
            {
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Const(item_const) if cfg_is_production_possible(&item_const.attrs) => {
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Static(item_static) if cfg_is_production_possible(&item_static.attrs) => {
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Trait(item_trait) if cfg_is_production_possible(&item_trait.attrs) => {
                self.scan_nested_items(item, source_path, event_scope);
            }
            Item::Type(item_type) if cfg_is_production_possible(&item_type.attrs) => {
                self.scan_nested_items(item, source_path, event_scope);
            }
            _ => {}
        }
    }

    fn scan_nested_items(&mut self, item: &Item, source_path: &Path, event_scope: &EventScope) {
        let mut visitor = NestedItemVisitor {
            scanner: self,
            source_path,
            event_scope,
        };
        syn::visit::visit_item(&mut visitor, item);
    }

    fn scan_event_declaration(
        &mut self,
        attrs: &[Attribute],
        ident: &syn::Ident,
        source_path: &Path,
    ) {
        if has_production_possible_derive(attrs)
            && let Some(span) = production_possible_cfg_attr_attribute(attrs, "event")
        {
            self.diagnostics.push(Diagnostic::new(
                self.location_from_span(source_path, span),
                "production-possible #[cfg_attr(..., event(...))] declarations are unsupported; use separate #[cfg(...)] Event declarations"
                    .to_string(),
            ));
            return;
        }
        if !has_event_derive(attrs) {
            return;
        }

        let start = ident.span().start();
        let location = self.location(source_path, start.line, start.column + 1);
        match event_name(attrs) {
            Ok(name) => match validate_event_name(&name) {
                Ok(()) => self.declarations.push(Declaration {
                    name,
                    event_type: ident.to_string(),
                    location,
                }),
                Err(error) => self.diagnostics.push(Diagnostic::new(
                    location,
                    format!("Event `{ident}` has an invalid identity: {error}"),
                )),
            },
            Err(message) => self.diagnostics.push(Diagnostic::new(
                location,
                format!("Event `{ident}` {message}"),
            )),
        }
    }

    fn finish(mut self) -> ScanReport {
        self.declarations.sort();
        self.declarations.dedup();
        self.diagnostics.sort();
        self.diagnostics.dedup();

        let mut by_name = BTreeMap::<&str, Vec<&Declaration>>::new();
        for declaration in &self.declarations {
            by_name
                .entry(&declaration.name)
                .or_default()
                .push(declaration);
        }
        for (name, declarations) in by_name {
            if declarations.len() < 2 {
                continue;
            }
            let locations = declarations
                .iter()
                .map(|declaration| format!("{} ({})", declaration.location, declaration.event_type))
                .collect::<Vec<_>>()
                .join(", ");
            self.diagnostics.push(Diagnostic::without_location(format!(
                "duplicate production Event event_name `{name}`: {locations}"
            )));
        }
        self.diagnostics.sort();
        self.diagnostics.dedup();

        ScanReport {
            declarations: self.declarations,
            diagnostics: self.diagnostics,
        }
    }

    fn location(&self, path: &Path, line: usize, column: usize) -> SourceLocation {
        SourceLocation {
            path: self.display_path(path),
            line,
            column,
        }
    }

    fn location_from_span(&self, path: &Path, span: proc_macro2::Span) -> SourceLocation {
        let start = span.start();
        self.location(path, start.line, start.column + 1)
    }

    fn display_path(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.workspace_root)
            .unwrap_or(path)
            .to_path_buf()
    }
}

struct NestedItemVisitor<'a> {
    scanner: &'a mut Scanner,
    source_path: &'a Path,
    event_scope: &'a EventScope,
}

// A cfg on any syntax container excludes its entire subtree. Gate each
// attrs-bearing container before syn descends into it; the generic Pat and
// FnArg hooks are both needed because syn dispatches some of their variants
// directly to more specific visitor methods.
impl<'ast> Visit<'ast> for NestedItemVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        self.scanner
            .scan_item(item, self.source_path, self.event_scope);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs = impl_item_attrs(item);
        if cfg_is_production_possible(attrs)
            && !matches!(item, syn::ImplItem::Fn(item) if is_test_or_bench(&item.attrs))
        {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs = trait_item_attrs(item);
        if cfg_is_production_possible(attrs)
            && !matches!(item, syn::TraitItem::Fn(item) if is_test_or_bench(&item.attrs))
        {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit_if_production_possible(self, &local.attrs, |visitor| {
            syn::visit::visit_local(visitor, local);
        });
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        visit_if_production_possible(self, expr_attrs(expression), |visitor| {
            syn::visit::visit_expr(visitor, expression);
        });
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        visit_if_production_possible(self, &arm.attrs, |visitor| {
            syn::visit::visit_arm(visitor, arm);
        });
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        visit_if_production_possible(self, &field.attrs, |visitor| {
            syn::visit::visit_field_value(visitor, field);
        });
    }

    fn visit_pat(&mut self, pattern: &'ast syn::Pat) {
        visit_if_production_possible(self, pat_attrs(pattern), |visitor| {
            syn::visit::visit_pat(visitor, pattern);
        });
    }

    fn visit_field_pat(&mut self, field: &'ast syn::FieldPat) {
        visit_if_production_possible(self, &field.attrs, |visitor| {
            syn::visit::visit_field_pat(visitor, field);
        });
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        visit_if_production_possible(self, &variant.attrs, |visitor| {
            syn::visit::visit_variant(visitor, variant);
        });
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        visit_if_production_possible(self, &field.attrs, |visitor| {
            syn::visit::visit_field(visitor, field);
        });
    }

    fn visit_generic_param(&mut self, parameter: &'ast syn::GenericParam) {
        visit_if_production_possible(self, generic_param_attrs(parameter), |visitor| {
            syn::visit::visit_generic_param(visitor, parameter);
        });
    }

    fn visit_fn_arg(&mut self, argument: &'ast syn::FnArg) {
        visit_if_production_possible(self, fn_arg_attrs(argument), |visitor| {
            syn::visit::visit_fn_arg(visitor, argument);
        });
    }

    fn visit_variadic(&mut self, variadic: &'ast syn::Variadic) {
        visit_if_production_possible(self, &variadic.attrs, |visitor| {
            syn::visit::visit_variadic(visitor, variadic);
        });
    }

    fn visit_bare_fn_arg(&mut self, argument: &'ast syn::BareFnArg) {
        visit_if_production_possible(self, &argument.attrs, |visitor| {
            syn::visit::visit_bare_fn_arg(visitor, argument);
        });
    }
}

fn visit_if_production_possible<'ast, V>(
    visitor: &mut V,
    attrs: &[Attribute],
    visit: impl FnOnce(&mut V),
) where
    V: Visit<'ast> + ?Sized,
{
    if cfg_is_production_possible(attrs) {
        visit(visitor);
    }
}

fn has_event_derive(attrs: &[Attribute]) -> bool {
    // A proc macro can be re-exported or imported under any local name, so the
    // derive path cannot establish ownership. `event` is the carbide-specific
    // registered helper attribute; requiring a derive as well keeps ordinary
    // attributes with the same spelling out of this declaration check.
    if !attrs.iter().any(|attr| attr.path().is_ident("event")) {
        return false;
    }

    has_production_possible_derive(attrs)
}

fn has_production_possible_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("derive"))
        || production_possible_cfg_attr_attribute(attrs, "derive").is_some()
}

fn has_event_impl_signature(item_impl: &syn::ItemImpl) -> bool {
    let mut event_name = false;
    let mut metric_name = false;
    let mut component = false;
    let mut labels = false;

    for item in &item_impl.items {
        match item {
            syn::ImplItem::Const(item) if item.ident == "EVENT_NAME" => event_name = true,
            syn::ImplItem::Const(item) if item.ident == "METRIC_NAME" => metric_name = true,
            syn::ImplItem::Const(item) if item.ident == "COMPONENT" => component = true,
            syn::ImplItem::Type(item) if item.ident == "Labels" => labels = true,
            _ => {}
        }
    }

    event_name && metric_name && component && labels
}

fn event_name(attrs: &[Attribute]) -> Result<String, String> {
    let mut names = Vec::new();
    let mut saw_event_attribute = false;

    for attr in attrs.iter().filter(|attr| attr.path().is_ident("event")) {
        saw_event_attribute = true;
        let metas = attr
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map_err(|error| format!("has an invalid #[event(...)] attribute: {error}"))?;
        for meta in metas {
            if !meta.path().is_ident("event_name") {
                continue;
            }
            let Meta::NameValue(name_value) = meta else {
                return Err("must declare event_name as `event_name = \"...\"`".to_string());
            };
            let Expr::Lit(expression) = name_value.value else {
                return Err("event_name must be a string literal".to_string());
            };
            let Lit::Str(name) = expression.lit else {
                return Err("event_name must be a string literal".to_string());
            };
            names.push(name.value());
        }
    }

    match names.as_slice() {
        [name] => Ok(name.clone()),
        [] if saw_event_attribute => Err("must declare `event_name = \"...\"`".to_string()),
        [] => Err("requires an #[event(event_name = \"...\", ...)] attribute".to_string()),
        _ => Err("declares event_name more than once".to_string()),
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Declaration {
    name: String,
    event_type: String,
    location: SourceLocation,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceLocation {
    path: PathBuf,
    line: usize,
    column: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.path.display(),
            self.line,
            self.column
        )
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Diagnostic {
    location: Option<SourceLocation>,
    message: String,
}

impl Diagnostic {
    fn new(location: SourceLocation, message: String) -> Self {
        Self {
            location: Some(location),
            message,
        }
    }

    fn without_location(message: String) -> Self {
        Self {
            location: None,
            message,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(location) = &self.location {
            write!(formatter, "{location}: error: {}", self.message)
        } else {
            write!(formatter, "error: {}", self.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "nico-xtask-event-names-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create fixture root");
            let root = root.canonicalize().expect("canonicalize fixture root");
            Self { root }
        }

        fn write(&self, relative_path: &str, source: &str) -> PathBuf {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture module directory");
            }
            fs::write(&path, source).expect("write fixture source");
            path
        }

        fn scan(&self, roots: &[&str]) -> ScanReport {
            let roots = roots
                .iter()
                .map(|root| self.root.join(root))
                .collect::<Vec<_>>();
            scan_roots(&self.root, roots.iter().map(PathBuf::as_path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove fixture root");
        }
    }

    fn event(name: &str, event_type: &str) -> String {
        format!(
            "#[derive(carbide_instrument::Event)]\n#[event(event_name = \"{name}\")]\nstruct {event_type};\n"
        )
    }

    fn manual_event_impl(trait_path: &str, event_type: &str) -> String {
        format!(
            "impl {trait_path} for {event_type} {{\n\
             const EVENT_NAME: &'static str = \"manual\";\n\
             const METRIC_NAME: Option<&'static str> = None;\n\
             const COMPONENT: &'static str = \"test\";\n\
             type Labels = [(); 0];\n\
             }}\n"
        )
    }

    fn messages(report: &ScanReport) -> Vec<String> {
        report.diagnostics.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn reports_duplicate_names_with_each_declaration() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!("mod nested;\n{}", event("same", "First")),
        );
        fixture.write("nested.rs", &event("same", "Second"));

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 2);
        assert_eq!(
            messages(&report),
            vec![
                "error: duplicate production Event event_name `same`: lib.rs:4:8 (First), nested.rs:3:8 (Second)"
            ]
        );
    }

    #[test]
    fn excludes_test_and_documentation_only_modules() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\n#[cfg(test)] mod tests {{ {} }}\n#[cfg(doc)] mod docs {{ {} }}\n#[cfg(docsrs)] mod docsrs {{ {} }}\n#[cfg(doctest)] mod doctests {{ {} }}",
                event("shared", "Production"),
                event("shared", "TestOnly"),
                event("shared", "DocOnly"),
                event("shared", "DocsrsOnly"),
                event("shared", "DoctestOnly"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn includes_feature_and_target_gated_declarations() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "#[cfg(feature = \"optional\")]\n{}\n#[cfg(target_os = \"linux\")]\n{}",
                event("gated", "FeatureGated"),
                event("gated", "TargetGated"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 2);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].message.contains("duplicate"));
    }

    #[test]
    fn follows_explicit_path_modules() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "#[path = \"events/custom.rs\"]\nmod custom;\n");
        fixture.write("events/custom.rs", &event("custom_event", "Custom"));

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "custom_event");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn resolves_paths_and_children_from_non_mod_rs_files() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "mod outer;\n");
        fixture.write("outer.rs", "mod nested;\n");
        fixture.write("outer/nested.rs", "#[path = \"events.rs\"]\nmod custom;\n");
        fixture.write("outer/events.rs", "mod child;\n");
        fixture.write(
            "outer/child.rs",
            &event("path_loaded_child", "PathLoadedChild"),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "path_loaded_child");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn honors_path_on_inline_modules() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[path = \"event_files\"]\nmod inline { mod declaration; }\n",
        );
        fixture.write(
            "event_files/declaration.rs",
            &event("inline_path_event", "InlinePathEvent"),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "inline_path_event");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn rejects_production_possible_conditional_module_paths() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[cfg_attr(feature = \"alternate\", path = \"alternate.rs\")]\nmod events;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 0);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .message
                .contains("production-possible #[cfg_attr(..., path = ...)]")
        );
    }

    #[test]
    fn ignores_test_only_conditional_module_paths() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[cfg_attr(test, path = \"test_events.rs\")]\nmod events;\n",
        );
        fixture.write("events.rs", &event("production_event", "ProductionEvent"));

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn rejects_production_possible_conditional_event_helpers() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[derive(carbide_instrument::Event)]\n\
             #[cfg_attr(feature = \"alternate\", event(event_name = \"conditional\"))]\n\
             struct ConditionalEvent;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert!(report.declarations.is_empty());
        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .message
                .contains("production-possible #[cfg_attr(..., event(...))]")
        );
    }

    #[test]
    fn ignores_test_only_conditional_event_helpers() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[derive(carbide_instrument::Event)]\n\
             #[event(event_name = \"production_event\")]\n\
             #[cfg_attr(test, event(event_name = \"test_event\"))]\n\
             struct ProductionEvent;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "production_event");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn recognizes_nested_production_possible_conditional_derives() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[cfg_attr(feature = \"outer\", cfg_attr(feature = \"inner\", derive(carbide_instrument::Event)))]\n\
             #[event(event_name = \"nested_conditional_derive\")]\n\
             struct NestedConditionalDerive;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "nested_conditional_derive");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn ignores_nested_conditional_derives_disabled_in_production() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[cfg_attr(feature = \"outer\", cfg_attr(doctest, derive(carbide_instrument::Event)))]\n\
             #[event(event_name = \"doctest_only_derive\")]\n\
             struct DoctestOnlyDerive;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert!(report.declarations.is_empty());
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn deduplicates_modules_reachable_from_multiple_targets() {
        let fixture = Fixture::new();
        fixture.write("shared.rs", &event("shared_event", "Shared"));
        fixture.write("lib.rs", "mod shared;\n");
        fixture.write(
            "main.rs",
            "#[path = \"shared.rs\"]\nmod shared_from_binary;\n",
        );

        let report = fixture.scan(&["main.rs", "lib.rs", "lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn revisits_shared_sources_under_distinct_module_resolution_contexts() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "mod shared;\n");
        fixture.write(
            "main.rs",
            "#[path = \"shared.rs\"]\nmod shared_from_binary;\n",
        );
        fixture.write(
            "shared.rs",
            &format!("{}\nmod nested;\n", event("direct", "Direct")),
        );
        fixture.write("shared/nested.rs", &event("contextual", "NormalNested"));
        fixture.write("nested.rs", &event("contextual", "PathNested"));

        let report = fixture.scan(&["lib.rs", "main.rs"]);

        assert_eq!(report.declarations.len(), 3);
        assert_eq!(
            messages(&report),
            vec![
                "error: duplicate production Event event_name `contextual`: shared/nested.rs:3:8 (NormalNested), nested.rs:3:8 (PathNested)"
            ]
        );
    }

    #[test]
    fn deduplicates_diagnostics_from_shared_source_locations() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "mod shared;\n");
        fixture.write(
            "main.rs",
            "#[path = \"shared.rs\"]\nmod shared_from_binary;\n",
        );
        fixture.write(
            "shared.rs",
            "#[derive(carbide_instrument::Event)]\n#[event(metric_name = \"metric\")]\nstruct Missing;\n",
        );

        let report = fixture.scan(&["lib.rs", "main.rs"]);

        assert!(report.declarations.is_empty());
        assert_eq!(
            messages(&report),
            vec!["shared.rs:3:8: error: Event `Missing` must declare `event_name = \"...\"`"]
        );
    }

    #[test]
    fn excludes_files_with_non_production_inner_cfg_attributes() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\nmod tests;\nmod docs;\nmod docsrs;\nmod doctests;\n",
                event("shared", "Production")
            ),
        );
        struct Case {
            module: &'static str,
            cfg: &'static str,
            event_type: &'static str,
        }

        for Case {
            module,
            cfg,
            event_type,
        } in [
            Case {
                module: "tests",
                cfg: "test",
                event_type: "TestOnly",
            },
            Case {
                module: "docs",
                cfg: "doc",
                event_type: "DocOnly",
            },
            Case {
                module: "docsrs",
                cfg: "docsrs",
                event_type: "DocsrsOnly",
            },
            Case {
                module: "doctests",
                cfg: "doctest",
                event_type: "DoctestOnly",
            },
        ] {
            fixture.write(
                &format!("{module}.rs"),
                &format!("#![cfg({cfg})]\n{}", event("shared", event_type)),
            );
        }

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn propagates_non_production_cfg_through_nested_ast_containers() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\n\
                 struct Holder {{ value: usize }}\n\
                 fn nested() {{\n\
                     #[cfg(test)]\n\
                     const {{ {} }}\n\
                     match () {{\n\
                         #[cfg(doctest)]\n\
                         () => {{ {} }},\n\
                         _ => {{}},\n\
                     }}\n\
                     let _ = Holder {{\n\
                         #[cfg(doc)]\n\
                         value: const {{ {} 0 }},\n\
                         ..Holder {{ value: 0 }}\n\
                     }};\n\
                     #[cfg(docsrs)]\n\
                     let _local = {{ {} 0 }};\n\
                     let _closure = |#[cfg(test)] _: [(); const {{ {} 0 }}]| {{}};\n\
                     let Holder {{\n\
                         #[cfg(doctest)]\n\
                         value: const {{ {} 0 }},\n\
                         ..\n\
                     }} = Holder {{ value: 0 }};\n\
                 }}\n\
                 struct FieldHolder {{\n\
                     #[cfg(test)]\n\
                     value: [(); const {{ {} 0 }}],\n\
                 }}\n\
                 enum VariantHolder {{\n\
                     #[cfg(doc)]\n\
                     Value([(); const {{ {} 0 }}]),\n\
                 }}\n\
                 struct GenericHolder<T,\n\
                     #[cfg(docsrs)]\n\
                     const N: usize = {{ {} 0 }},\n\
                 >(std::marker::PhantomData<T>);\n\
                 trait Associated {{\n\
                     #[cfg(doctest)]\n\
                     const VALUE: usize = {{ {} 0 }};\n\
                 }}\n\
                 impl Holder {{\n\
                     #[cfg(test)]\n\
                     const VALUE: usize = {{ {} 0 }};\n\
                 }}\n\
                 fn argument(#[cfg(doc)] _: [(); const {{ {} 0 }}]) {{}}\n\
                 type Callback = fn(#[cfg(test)] [(); const {{ {} 0 }}]);\n",
                event("shared", "Production"),
                event("shared", "ExpressionOnly"),
                event("shared", "ArmOnly"),
                event("shared", "FieldValueOnly"),
                event("shared", "LocalOnly"),
                event("shared", "PatternOnly"),
                event("shared", "FieldPatternOnly"),
                event("shared", "FieldOnly"),
                event("shared", "VariantOnly"),
                event("shared", "GenericOnly"),
                event("shared", "TraitItemOnly"),
                event("shared", "ImplItemOnly"),
                event("shared", "ArgumentOnly"),
                event("shared", "BareArgumentOnly"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1, "{:#?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn includes_direct_declarations_in_production_bodies() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\nfn declare_local() {{ {} }}\nconst LOCAL_CONST: () = {{ {} }};\nstatic LOCAL_STATIC: () = {{ {} }};",
                event("same", "ModuleEvent"),
                event("same", "FunctionEvent"),
                event("const_event", "ConstEvent"),
                event("static_event", "StaticEvent"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 4);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0].message.contains("FunctionEvent"));
        assert!(report.diagnostics[0].message.contains("ModuleEvent"));
    }

    #[test]
    fn excludes_direct_declarations_in_test_and_bench_functions() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\n#[test] fn test_event() {{ {} }}\n#[bench] fn bench_event() {{ {} }}\n#[tokio::test] async fn macro_test_event() {{ {} }}\nstruct Holder;\nimpl Holder {{ #[cfg(test)] fn cfg_test_method() {{ {} }} }}",
                event("shared", "Production"),
                event("shared", "TestOnly"),
                event("shared", "BenchOnly"),
                event("shared", "MacroTestOnly"),
                event("shared", "CfgTestMethodOnly"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn handles_nested_conditional_test_attributes() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "{}\n\
                 #[cfg_attr(not(test), cfg_attr(not(doc), test))]\n\
                 fn nested_test_event() {{ {} }}\n\
                 #[cfg_attr(feature = \"test-helper\", cfg_attr(not(doc), test))]\n\
                 fn conditionally_production_event() {{ {} }}",
                event("shared", "Production"),
                event("shared", "NestedTestOnly"),
                event("conditionally_production", "ConditionallyProduction"),
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            report
                .declarations
                .iter()
                .map(|declaration| declaration.name.as_str())
                .collect::<Vec<_>>(),
            vec!["conditionally_production", "shared"]
        );
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn reports_missing_handwritten_modules() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "mod missing;\n");

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            messages(&report),
            vec!["lib.rs:1:5: error: could not find source for module `missing`"]
        );
    }

    #[test]
    fn always_skips_known_generated_source_directories() {
        let fixture = Fixture::new();
        let crate_root = "crates/ssh-console-mock-api-server/src";
        fixture.write(
            &format!("{crate_root}/lib.rs"),
            &format!("{}\nmod generated;\n", event("shared", "Production")),
        );
        fixture.write(
            &format!("{crate_root}/generated/mod.rs"),
            "mod generated_at_build_time;\n",
        );
        fixture.write(
            &format!("{crate_root}/generated/generated_at_build_time.rs"),
            &event("shared", "Generated"),
        );

        let report = fixture.scan(&[&format!("{crate_root}/lib.rs")]);

        assert_eq!(report.declarations.len(), 1);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn gitignore_does_not_hide_missing_handwritten_modules() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "mod ordinary;\n");
        fixture.write("ordinary/mod.rs", "mod missing;\n");
        fixture.write("ordinary/.gitignore", "*\n");

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            messages(&report),
            vec!["ordinary/mod.rs:1:5: error: could not find source for module `missing`"]
        );
    }

    #[test]
    fn reports_missing_and_nonliteral_names() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[derive(carbide_instrument::Event)]\n#[event(metric_name = \"metric\")]\nstruct Missing;\n\n#[derive(carbide_instrument::Event)]\n#[event(event_name = concat!(\"not\", \"literal\"))]\nstruct Nonliteral;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            messages(&report),
            vec![
                "lib.rs:3:8: error: Event `Missing` must declare `event_name = \"...\"`",
                "lib.rs:7:8: error: Event `Nonliteral` event_name must be a string literal",
            ]
        );
    }

    #[test]
    fn recognizes_arbitrarily_aliased_instrument_event_derives() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "use carbide_instrument::Event as Instrument;\n\
             #[derive(Instrument)]\n\
             #[event(event_name = \"imported_event\")]\n\
             struct ImportedEvent;\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.declarations.len(), 1);
        assert_eq!(report.declarations[0].name, "imported_event");
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn ignores_unrelated_event_derives_and_traits() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "#[derive(other::Event)]\n\
             struct QualifiedUnrelated;\n\
             #[derive(Event)]\n\
             struct BareUnrelated;\n\
             impl other::Event for QualifiedUnrelated {}\n\
             impl Event for BareUnrelated {}\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert!(report.declarations.is_empty());
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn rejects_manual_event_implementations_through_an_import() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            "use carbide_instrument::Event;\nstruct Manual;\nimpl Event for Manual {}\n",
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .message
                .contains("manual Event implementations are unsupported")
        );
    }

    #[test]
    fn rejects_manual_event_implementations_through_reexports() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "struct Manual;\n{}",
                manual_event_impl("facade::TypedOccurrence", "Manual")
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .message
                .contains("manual Event implementations are unsupported")
        );
    }

    #[test]
    fn rejects_manual_event_implementations_through_local_aliases() {
        let fixture = Fixture::new();
        fixture.write(
            "lib.rs",
            &format!(
                "fn declare() {{\n\
                 use facade::TypedOccurrence as LocalOccurrence;\n\
                 struct Manual;\n\
                 {}\n\
                 }}\n",
                manual_event_impl("LocalOccurrence", "Manual")
            ),
        );

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .message
                .contains("manual Event implementations are unsupported")
        );
    }

    #[test]
    fn uses_the_shared_event_name_grammar() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", &event("not.namespaced", "Namespaced"));

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            messages(&report),
            vec![
                "lib.rs:3:8: error: Event `Namespaced` has an invalid identity: event_name must be non-empty ASCII lower_snake_case, start with a letter, and contain no empty segments"
            ]
        );
    }

    #[test]
    fn rejects_manual_event_implementations() {
        let fixture = Fixture::new();
        fixture.write("lib.rs", "impl carbide_instrument::Event for Manual {}\n");

        let report = fixture.scan(&["lib.rs"]);

        assert_eq!(
            messages(&report),
            vec![
                "lib.rs:1:1: error: manual Event implementations are unsupported; use #[derive(Event)]"
            ]
        );
    }
}
