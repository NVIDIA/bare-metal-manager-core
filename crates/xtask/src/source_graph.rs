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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::{fmt, fs};

use cargo_metadata::{MetadataCommand, Package, Target};
use eyre::Context;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, Item, Lit, Meta, Token};

// These roots point at build-script output written beside the source tree.
// We still fail closed for every other missing module so a new blind spot has
// to be reviewed before it becomes part of the production scan.
const GENERATED_SOURCE_DIRECTORIES: &[&str] = &["crates/ssh-console-mock-api-server/src/generated"];

#[derive(Debug)]
pub(crate) struct SourceGraph {
    pub(crate) workspace_root: PathBuf,
    pub(crate) files_scanned: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

pub(crate) fn workspace(visit: impl FnMut(&Path, &Path, &syn::File)) -> eyre::Result<SourceGraph> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("failed to run cargo metadata")?;
    let workspace_root = metadata
        .workspace_root
        .canonicalize()
        .context("failed to resolve the workspace root")?;

    let mut roots = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .flat_map(production_roots)
        .collect::<Vec<_>>();
    roots.sort();

    Ok(scan_roots(
        &workspace_root,
        roots.iter().map(|root| root.path.as_path()),
        visit,
    ))
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TargetRoot {
    package: String,
    target: String,
    path: PathBuf,
}

fn production_roots(package: &Package) -> impl Iterator<Item = TargetRoot> + '_ {
    package
        .targets
        .iter()
        .filter(|target| is_production_target(target))
        .map(|target| TargetRoot {
            package: package.name.clone(),
            target: target.name.clone(),
            path: target.src_path.clone(),
        })
}

fn is_production_target(target: &Target) -> bool {
    target.kind.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "bin" | "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
        )
    })
}

pub(crate) fn scan_roots<'a>(
    workspace_root: &Path,
    roots: impl IntoIterator<Item = &'a Path>,
    visit: impl FnMut(&Path, &Path, &syn::File),
) -> SourceGraph {
    let mut scanner = Scanner::new(workspace_root, visit);
    let mut roots = roots.into_iter().map(Path::to_path_buf).collect::<Vec<_>>();
    roots.sort();

    for root in roots {
        let module_dir = root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| workspace_root.to_path_buf());
        scanner.scan_file(&root, &module_dir);
    }

    scanner.finish()
}

struct Scanner<F> {
    workspace_root: PathBuf,
    visited: BTreeSet<ModuleVisit>,
    emitted_files: BTreeSet<PathBuf>,
    diagnostics: Vec<Diagnostic>,
    visit: F,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModuleVisit {
    source_path: PathBuf,
    module_dir: PathBuf,
}

impl<F> Scanner<F>
where
    F: FnMut(&Path, &Path, &syn::File),
{
    fn new(workspace_root: &Path, visit: F) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            visited: BTreeSet::new(),
            emitted_files: BTreeSet::new(),
            diagnostics: Vec::new(),
            visit,
        }
    }

    fn scan_file(&mut self, path: &Path, module_dir: &Path) {
        let canonical_path = match path.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                self.diagnostics.push(Diagnostic::new(
                    self.location(path, 1, 1),
                    format!("could not resolve module source: {error}"),
                ));
                return;
            }
        };

        let module_dir = module_dir
            .canonicalize()
            .unwrap_or_else(|_| module_dir.to_path_buf());
        if !self.visited.insert(ModuleVisit {
            source_path: canonical_path.clone(),
            module_dir: module_dir.clone(),
        }) {
            return;
        }

        let source = match fs::read_to_string(&canonical_path) {
            Ok(source) => source,
            Err(error) => {
                self.diagnostics.push(Diagnostic::new(
                    self.location(&canonical_path, 1, 1),
                    format!("could not read module source: {error}"),
                ));
                return;
            }
        };
        let syntax = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                let start = error.span().start();
                self.diagnostics.push(Diagnostic::new(
                    self.location(&canonical_path, start.line, start.column + 1),
                    format!("could not parse module source: {error}"),
                ));
                return;
            }
        };
        if !cfg_is_production_possible(&syntax.attrs) {
            return;
        }

        if self.emitted_files.insert(canonical_path.clone()) {
            (self.visit)(&self.workspace_root, &canonical_path, &syntax);
        }

        let path_attr_dir = canonical_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.workspace_root.clone());
        self.scan_items(&syntax.items, &canonical_path, &module_dir, &path_attr_dir);
    }

    fn scan_items(
        &mut self,
        items: &[Item],
        source_path: &Path,
        module_dir: &Path,
        path_attr_dir: &Path,
    ) {
        for item in items {
            self.scan_item(item, source_path, module_dir, path_attr_dir);
        }
    }

    fn scan_item(
        &mut self,
        item: &Item,
        source_path: &Path,
        module_dir: &Path,
        path_attr_dir: &Path,
    ) {
        match item {
            Item::Mod(item_mod) if cfg_is_production_possible(&item_mod.attrs) => {
                if item_mod.content.is_none() && self.is_generated_source_directory(module_dir) {
                    return;
                }
                if let Some(span) = production_possible_cfg_attr_attribute(&item_mod.attrs, "path")
                {
                    self.diagnostics.push(Diagnostic::new(
                        self.location_from_span(source_path, span),
                        "production-possible #[cfg_attr(..., path = ...)] modules are unsupported; use separate #[cfg(...)] #[path = ...] module declarations"
                            .to_string(),
                    ));
                    return;
                }

                let explicit_path = match explicit_module_path(&item_mod.attrs) {
                    Ok(path) => path,
                    Err(error) => {
                        self.diagnostics.push(Diagnostic::new(
                            self.location_from_span(source_path, error.span()),
                            error.to_string(),
                        ));
                        return;
                    }
                };
                let nested_module_dir = explicit_path
                    .as_ref()
                    .map(|path| path_attr_dir.join(path))
                    .unwrap_or_else(|| module_dir.join(item_mod.ident.to_string()));
                if let Some((_, items)) = &item_mod.content {
                    self.scan_items(items, source_path, &nested_module_dir, &nested_module_dir);
                } else {
                    self.scan_external_module(
                        &item_mod.attrs,
                        &item_mod.ident,
                        source_path,
                        module_dir,
                        path_attr_dir,
                        &nested_module_dir,
                    );
                }
            }
            Item::Fn(item_fn)
                if cfg_is_production_possible(&item_fn.attrs)
                    && !is_test_or_bench(&item_fn.attrs) =>
            {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Struct(item_struct) if cfg_is_production_possible(&item_struct.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Enum(item_enum) if cfg_is_production_possible(&item_enum.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Union(item_union) if cfg_is_production_possible(&item_union.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Impl(item_impl) if cfg_is_production_possible(&item_impl.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Const(item_const) if cfg_is_production_possible(&item_const.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Static(item_static) if cfg_is_production_possible(&item_static.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Trait(item_trait) if cfg_is_production_possible(&item_trait.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            Item::Type(item_type) if cfg_is_production_possible(&item_type.attrs) => {
                self.scan_nested_items(item, source_path, module_dir, path_attr_dir);
            }
            _ => {}
        }
    }

    fn scan_nested_items(
        &mut self,
        item: &Item,
        source_path: &Path,
        module_dir: &Path,
        path_attr_dir: &Path,
    ) {
        let mut visitor = NestedItemVisitor {
            scanner: self,
            source_path,
            module_dir,
            path_attr_dir,
        };
        syn::visit::visit_item(&mut visitor, item);
    }

    fn scan_external_module(
        &mut self,
        attrs: &[Attribute],
        module_ident: &syn::Ident,
        source_path: &Path,
        module_dir: &Path,
        path_attr_dir: &Path,
        nested_module_dir: &Path,
    ) {
        let module_name = module_ident.to_string();
        match explicit_module_path(attrs) {
            Ok(Some(relative_path)) => {
                let path = path_attr_dir.join(relative_path);
                let child_module_dir = path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path_attr_dir.to_path_buf());
                self.scan_file(&path, &child_module_dir);
            }
            Ok(None) => {
                let candidates = [
                    module_dir.join(format!("{module_name}.rs")),
                    module_dir.join(&module_name).join("mod.rs"),
                ];
                let existing = candidates
                    .iter()
                    .filter(|candidate| candidate.is_file())
                    .collect::<Vec<_>>();
                match existing.as_slice() {
                    [path] => self.scan_file(path, nested_module_dir),
                    [] => self.diagnostics.push(Diagnostic::new(
                        self.location_from_span(source_path, module_ident.span()),
                        format!("could not find source for module `{module_name}`"),
                    )),
                    _ => self.diagnostics.push(Diagnostic::new(
                        self.location_from_span(source_path, attrs_span(attrs)),
                        format!(
                            "module `{module_name}` is ambiguous; both {} and {} exist",
                            self.display_path(&candidates[0]).display(),
                            self.display_path(&candidates[1]).display()
                        ),
                    )),
                }
            }
            Err(error) => self.diagnostics.push(Diagnostic::new(
                self.location_from_span(source_path, error.span()),
                error.to_string(),
            )),
        }
    }

    fn finish(mut self) -> SourceGraph {
        self.diagnostics.sort();
        self.diagnostics.dedup();
        SourceGraph {
            workspace_root: self.workspace_root,
            files_scanned: self.emitted_files.len(),
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

    fn is_generated_source_directory(&self, path: &Path) -> bool {
        let Ok(relative_path) = path.strip_prefix(&self.workspace_root) else {
            return false;
        };
        GENERATED_SOURCE_DIRECTORIES
            .iter()
            .any(|generated| relative_path == Path::new(generated))
    }
}

struct NestedItemVisitor<'a, F> {
    scanner: &'a mut Scanner<F>,
    source_path: &'a Path,
    module_dir: &'a Path,
    path_attr_dir: &'a Path,
}

// A cfg on a syntax container excludes the full subtree. These hooks keep
// nested functions, expressions, patterns, and fields on the same production
// boundary as their containing module.
impl<'ast, F> Visit<'ast> for NestedItemVisitor<'_, F>
where
    F: FnMut(&Path, &Path, &syn::File),
{
    fn visit_item(&mut self, item: &'ast Item) {
        self.scanner
            .scan_item(item, self.source_path, self.module_dir, self.path_attr_dir);
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

pub(crate) fn cfg_is_production_possible(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .all(|attr| cfg_attribute_truth(attr) != Truth::False)
}

pub(crate) fn is_test_or_bench(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if path_ends_in_test_or_bench(attr.path()) {
            return true;
        }
        if !attr.path().is_ident("cfg_attr") {
            return false;
        }

        let Ok(parts) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            return false;
        };
        cfg_attr_attribute_matching(
            &parts,
            CfgAttrConditionPolicy::DefinitelyActive,
            path_ends_in_test_or_bench,
        )
        .is_some()
    })
}

pub(crate) fn expr_attrs(expression: &Expr) -> &[Attribute] {
    match expression {
        Expr::Array(expression) => &expression.attrs,
        Expr::Assign(expression) => &expression.attrs,
        Expr::Async(expression) => &expression.attrs,
        Expr::Await(expression) => &expression.attrs,
        Expr::Binary(expression) => &expression.attrs,
        Expr::Block(expression) => &expression.attrs,
        Expr::Break(expression) => &expression.attrs,
        Expr::Call(expression) => &expression.attrs,
        Expr::Cast(expression) => &expression.attrs,
        Expr::Closure(expression) => &expression.attrs,
        Expr::Const(expression) => &expression.attrs,
        Expr::Continue(expression) => &expression.attrs,
        Expr::Field(expression) => &expression.attrs,
        Expr::ForLoop(expression) => &expression.attrs,
        Expr::Group(expression) => &expression.attrs,
        Expr::If(expression) => &expression.attrs,
        Expr::Index(expression) => &expression.attrs,
        Expr::Infer(expression) => &expression.attrs,
        Expr::Let(expression) => &expression.attrs,
        Expr::Lit(expression) => &expression.attrs,
        Expr::Loop(expression) => &expression.attrs,
        Expr::Macro(expression) => &expression.attrs,
        Expr::Match(expression) => &expression.attrs,
        Expr::MethodCall(expression) => &expression.attrs,
        Expr::Paren(expression) => &expression.attrs,
        Expr::Path(expression) => &expression.attrs,
        Expr::Range(expression) => &expression.attrs,
        Expr::RawAddr(expression) => &expression.attrs,
        Expr::Reference(expression) => &expression.attrs,
        Expr::Repeat(expression) => &expression.attrs,
        Expr::Return(expression) => &expression.attrs,
        Expr::Struct(expression) => &expression.attrs,
        Expr::Try(expression) => &expression.attrs,
        Expr::TryBlock(expression) => &expression.attrs,
        Expr::Tuple(expression) => &expression.attrs,
        Expr::Unary(expression) => &expression.attrs,
        Expr::Unsafe(expression) => &expression.attrs,
        Expr::While(expression) => &expression.attrs,
        Expr::Yield(expression) => &expression.attrs,
        Expr::Verbatim(_) => &[],
        _ => &[],
    }
}

pub(crate) fn impl_item_attrs(item: &syn::ImplItem) -> &[Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Verbatim(_) => &[],
        _ => &[],
    }
}

pub(crate) fn trait_item_attrs(item: &syn::TraitItem) -> &[Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Verbatim(_) => &[],
        _ => &[],
    }
}

pub(crate) fn pat_attrs(pattern: &syn::Pat) -> &[Attribute] {
    match pattern {
        syn::Pat::Const(pattern) => &pattern.attrs,
        syn::Pat::Ident(pattern) => &pattern.attrs,
        syn::Pat::Lit(pattern) => &pattern.attrs,
        syn::Pat::Macro(pattern) => &pattern.attrs,
        syn::Pat::Or(pattern) => &pattern.attrs,
        syn::Pat::Paren(pattern) => &pattern.attrs,
        syn::Pat::Path(pattern) => &pattern.attrs,
        syn::Pat::Range(pattern) => &pattern.attrs,
        syn::Pat::Reference(pattern) => &pattern.attrs,
        syn::Pat::Rest(pattern) => &pattern.attrs,
        syn::Pat::Slice(pattern) => &pattern.attrs,
        syn::Pat::Struct(pattern) => &pattern.attrs,
        syn::Pat::Tuple(pattern) => &pattern.attrs,
        syn::Pat::TupleStruct(pattern) => &pattern.attrs,
        syn::Pat::Type(pattern) => &pattern.attrs,
        syn::Pat::Wild(pattern) => &pattern.attrs,
        syn::Pat::Verbatim(_) => &[],
        _ => &[],
    }
}

pub(crate) fn generic_param_attrs(parameter: &syn::GenericParam) -> &[Attribute] {
    match parameter {
        syn::GenericParam::Lifetime(parameter) => &parameter.attrs,
        syn::GenericParam::Type(parameter) => &parameter.attrs,
        syn::GenericParam::Const(parameter) => &parameter.attrs,
    }
}

pub(crate) fn fn_arg_attrs(argument: &syn::FnArg) -> &[Attribute] {
    match argument {
        syn::FnArg::Receiver(argument) => &argument.attrs,
        syn::FnArg::Typed(argument) => &argument.attrs,
    }
}

fn explicit_module_path(attrs: &[Attribute]) -> syn::Result<Option<PathBuf>> {
    let mut paths = attrs.iter().filter(|attr| attr.path().is_ident("path"));
    let Some(attr) = paths.next() else {
        return Ok(None);
    };
    if paths.next().is_some() {
        return Err(syn::Error::new_spanned(
            attr,
            "module has more than one #[path] attribute",
        ));
    }

    match &attr.meta {
        Meta::NameValue(name_value) => match &name_value.value {
            Expr::Lit(expr) => match &expr.lit {
                Lit::Str(path) => Ok(Some(PathBuf::from(path.value()))),
                _ => Err(syn::Error::new_spanned(
                    &name_value.value,
                    "module #[path] must be a string literal",
                )),
            },
            expression => Err(syn::Error::new_spanned(
                expression,
                "module #[path] must be a string literal",
            )),
        },
        _ => Err(syn::Error::new_spanned(
            attr,
            "module #[path] must be written as #[path = \"...\"]",
        )),
    }
}

pub(crate) fn production_possible_cfg_attr_attribute(
    attrs: &[Attribute],
    attribute_name: &str,
) -> Option<proc_macro2::Span> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg_attr"))
        .find_map(|attr| {
            let parts = attr
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok()?;
            cfg_attr_attribute_matching(
                &parts,
                CfgAttrConditionPolicy::ProductionPossible,
                |path| path.is_ident(attribute_name),
            )
        })
}

#[derive(Clone, Copy)]
enum CfgAttrConditionPolicy {
    ProductionPossible,
    DefinitelyActive,
}

impl CfgAttrConditionPolicy {
    fn accepts(self, truth: Truth) -> bool {
        match self {
            Self::ProductionPossible => truth != Truth::False,
            Self::DefinitelyActive => truth == Truth::True,
        }
    }
}

fn cfg_attr_attribute_matching<F>(
    parts: &Punctuated<Meta, Token![,]>,
    condition_policy: CfgAttrConditionPolicy,
    attribute_matches: F,
) -> Option<proc_macro2::Span>
where
    F: Fn(&syn::Path) -> bool + Copy,
{
    let mut parts = parts.iter();
    let condition = parts.next()?;
    if !condition_policy.accepts(cfg_truth(condition)) {
        return None;
    }

    parts.find_map(|meta| {
        if attribute_matches(meta.path()) {
            return Some(meta.span());
        }
        let Meta::List(list) = meta else {
            return None;
        };
        if !list.path.is_ident("cfg_attr") {
            return None;
        }
        let nested = Punctuated::<Meta, Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .ok()?;
        cfg_attr_attribute_matching(&nested, condition_policy, attribute_matches)
    })
}

fn attrs_span(attrs: &[Attribute]) -> proc_macro2::Span {
    attrs
        .first()
        .map(Spanned::span)
        .unwrap_or_else(proc_macro2::Span::call_site)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Unknown,
}

fn path_ends_in_test_or_bench(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == "test" || segment.ident == "bench")
}

fn cfg_attribute_truth(attr: &Attribute) -> Truth {
    if attr.path().is_ident("cfg") {
        return attr
            .parse_args::<Meta>()
            .map_or(Truth::Unknown, |meta| cfg_truth(&meta));
    }
    if !attr.path().is_ident("cfg_attr") {
        return Truth::True;
    }

    let Ok(parts) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return Truth::Unknown;
    };
    let mut parts = parts.iter();
    let Some(condition) = parts.next() else {
        return Truth::Unknown;
    };
    match cfg_truth(condition) {
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
        Truth::True => parts.fold(Truth::True, |current, meta| {
            and(current, nested_cfg_truth(meta))
        }),
    }
}

fn nested_cfg_truth(meta: &Meta) -> Truth {
    match meta {
        Meta::List(list) if list.path.is_ident("cfg") => {
            syn::parse2::<Meta>(list.tokens.clone()).map_or(Truth::Unknown, |meta| cfg_truth(&meta))
        }
        Meta::List(list) if list.path.is_ident("cfg_attr") => {
            Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .map_or(Truth::Unknown, |parts| {
                    let mut parts = parts.iter();
                    let Some(condition) = parts.next() else {
                        return Truth::Unknown;
                    };
                    match cfg_truth(condition) {
                        Truth::False => Truth::True,
                        Truth::Unknown => Truth::Unknown,
                        Truth::True => parts.fold(Truth::True, |current, meta| {
                            and(current, nested_cfg_truth(meta))
                        }),
                    }
                })
        }
        _ => Truth::True,
    }
}

fn cfg_truth(meta: &Meta) -> Truth {
    match meta {
        Meta::Path(path)
            if path.is_ident("test")
                || path.is_ident("doc")
                || path.is_ident("docsrs")
                || path.is_ident("doctest") =>
        {
            Truth::False
        }
        Meta::Path(_) | Meta::NameValue(_) => Truth::Unknown,
        Meta::List(list) if list.path.is_ident("all") => {
            let Ok(parts) =
                Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
            else {
                return Truth::Unknown;
            };
            parts
                .iter()
                .fold(Truth::True, |current, meta| and(current, cfg_truth(meta)))
        }
        Meta::List(list) if list.path.is_ident("any") => {
            let Ok(parts) =
                Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
            else {
                return Truth::Unknown;
            };
            parts
                .iter()
                .fold(Truth::False, |current, meta| or(current, cfg_truth(meta)))
        }
        Meta::List(list) if list.path.is_ident("not") => {
            let Ok(parts) =
                Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
            else {
                return Truth::Unknown;
            };
            let mut parts = parts.iter();
            match (parts.next(), parts.next()) {
                (Some(meta), None) => not(cfg_truth(meta)),
                _ => Truth::Unknown,
            }
        }
        Meta::List(_) => Truth::Unknown,
    }
}

fn and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceLocation {
    pub(crate) path: PathBuf,
    pub(crate) line: usize,
    pub(crate) column: usize,
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
pub(crate) struct Diagnostic {
    pub(crate) location: Option<SourceLocation>,
    pub(crate) message: String,
}

impl Diagnostic {
    fn new(location: SourceLocation, message: String) -> Self {
        Self {
            location: Some(location),
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
