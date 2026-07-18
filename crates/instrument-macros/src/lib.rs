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

//! Derive macros for `carbide-instrument`: `#[derive(Event)]` and
//! `#[derive(LabelValue)]`. See the `carbide-instrument` crate documentation
//! for the model and usage; these macros are re-exported from there.

use carbide_observability_schema::{is_event_log_reserved_field, validate_event_name};
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Field, Fields, Ident, LitStr};

/// Metric-name unit suffixes a histogram may use, with the OpenTelemetry unit
/// string each one implies.
const UNIT_SUFFIXES: &[(&str, &str)] = &[
    ("_seconds", "s"),
    ("_milliseconds", "ms"),
    ("_microseconds", "us"),
    ("_bytes", "By"),
];

/// Derives `carbide_instrument::LabelValue` for a fieldless enum: each variant
/// renders as its snake_case name. Enums are the only derivable label type --
/// that is the cardinality guarantee. For a bounded-but-not-enum value,
/// implement `LabelValue` by hand on a newtype (the reviewed escape hatch).
#[proc_macro_derive(LabelValue)]
pub fn derive_label_value(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    match expand_label_value(input) {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_label_value(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "LabelValue can only be derived for enums: metric label values must come from a \
             closed set. For a bounded-but-not-enum value, implement LabelValue by hand on a \
             newtype.",
        ));
    };
    if data.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "LabelValue needs at least one variant",
        ));
    }

    let mut arms = Vec::new();
    for variant in &data.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "LabelValue variants must be unit variants (no fields): the label value set \
                 must be closed",
            ));
        }
        let ident = &variant.ident;
        let value = snake_case(&ident.to_string());
        arms.push(quote! { Self::#ident => #value, });
    }

    Ok(quote! {
        impl ::carbide_instrument::LabelValue for #name {
            fn label_value(&self) -> ::carbide_instrument::__private::opentelemetry::StringValue {
                ::carbide_instrument::__private::opentelemetry::StringValue::from(match self {
                    #(#arms)*
                })
            }
        }
    }
    .into())
}

/// Derives `carbide_instrument::Event` for a struct declared with an
/// `#[event(...)]` attribute. Every field takes exactly one of `#[label]`
/// (enum via `LabelValue`; goes to both the log line and the metric),
/// `#[context]` (any `Display`; log-only), or `#[observation]` (the histogram
/// value). The metric name is validated at compile time: `carbide_` prefix,
/// `_total` for counters (never a doubled `_total_total`), a unit suffix for
/// histograms. A counter's `describe` is checked too -- present and opening
/// with "Number of ..." -- with `describe_unchecked` as the escape hatch for
/// grandfathered text, mirroring `metric_name_unchecked` for names.
#[proc_macro_derive(Event, attributes(event, label, context, observation))]
pub fn derive_event(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    match expand_event(input) {
        Ok(ts) => ts,
        Err(e) => e.to_compile_error().into(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum LogSpec {
    Off,
    Dynamic,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Copy, PartialEq)]
enum MetricSpec {
    Counter,
    Histogram,
    None,
}

struct EventArgs {
    event_name: Option<LitStr>,
    metric_name: Option<LitStr>,
    component: Option<LitStr>,
    message: Option<LitStr>,
    describe: Option<LitStr>,
    unit: Option<LitStr>,
    log: LogSpec,
    metric: MetricSpec,
    metric_name_unchecked: bool,
    describe_unchecked: bool,
}

fn parse_event_args(input: &DeriveInput) -> syn::Result<EventArgs> {
    let mut args = EventArgs {
        event_name: None,
        metric_name: None,
        component: None,
        message: None,
        describe: None,
        unit: None,
        log: LogSpec::Info,
        metric: MetricSpec::None,
        metric_name_unchecked: false,
        describe_unchecked: false,
    };
    let mut saw_attr = false;

    for attr in &input.attrs {
        if !attr.path().is_ident("event") {
            continue;
        }
        saw_attr = true;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("event_name") {
                if args.event_name.is_some() {
                    return Err(meta.error("duplicate `event_name`"));
                }
                args.event_name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("metric_name") {
                if args.metric_name.is_some() {
                    return Err(meta.error("duplicate `metric_name`"));
                }
                args.metric_name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("name") {
                return Err(meta.error(
                    "`name` has been split into `event_name` and `metric_name`; every Event \
                     needs event_name, and metric-backed Events also need metric_name",
                ));
            } else if meta.path.is_ident("component") {
                args.component = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("message") {
                args.message = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("describe") {
                args.describe = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("unit") {
                args.unit = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("metric_name_unchecked") {
                args.metric_name_unchecked = true;
            } else if meta.path.is_ident("name_unchecked") {
                return Err(meta.error(
                    "`name_unchecked` was renamed to `metric_name_unchecked` because it only \
                     relaxes validation of a grandfathered metric name",
                ));
            } else if meta.path.is_ident("describe_unchecked") {
                args.describe_unchecked = true;
            } else if meta.path.is_ident("log") {
                let ident: Ident = meta.value()?.parse()?;
                args.log = match ident.to_string().as_str() {
                    "off" => LogSpec::Off,
                    "dynamic" => LogSpec::Dynamic,
                    "error" => LogSpec::Error,
                    "warn" => LogSpec::Warn,
                    "info" => LogSpec::Info,
                    "debug" => LogSpec::Debug,
                    "trace" => LogSpec::Trace,
                    other => {
                        return Err(meta.error(format!(
                            "unknown log level `{other}`; expected one of \
                             error | warn | info | debug | trace | off | dynamic"
                        )));
                    }
                };
            } else if meta.path.is_ident("metric") {
                let ident: Ident = meta.value()?.parse()?;
                args.metric = match ident.to_string().as_str() {
                    "counter" => MetricSpec::Counter,
                    "histogram" => MetricSpec::Histogram,
                    "none" => MetricSpec::None,
                    other => {
                        return Err(meta.error(format!(
                            "unknown metric kind `{other}`; expected counter | histogram | none"
                        )));
                    }
                };
            } else {
                return Err(meta.error(
                    "unknown `event` key; expected event_name, metric_name, component, message, \
                     describe, log, metric, unit, metric_name_unchecked, or describe_unchecked",
                ));
            }
            Ok(())
        })?;
    }

    if !saw_attr {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "deriving Event requires an #[event(event_name = ..., component = ..., ...)] \
             attribute",
        ));
    }
    Ok(args)
}

#[derive(Clone, Copy, PartialEq)]
enum FieldKind {
    Label,
    Context,
    Observation,
}

fn classify_field(field: &Field) -> syn::Result<FieldKind> {
    let mut kinds = Vec::new();
    for attr in &field.attrs {
        if attr.path().is_ident("label") {
            kinds.push(FieldKind::Label);
        } else if attr.path().is_ident("context") {
            kinds.push(FieldKind::Context);
        } else if attr.path().is_ident("observation") {
            kinds.push(FieldKind::Observation);
        }
    }
    match kinds.as_slice() {
        [kind] => Ok(*kind),
        [] => Err(syn::Error::new_spanned(
            field,
            "every Event field needs exactly one of #[label] (bounded, on the metric and the \
             log), #[context] (log-only), or #[observation] (the histogram value)",
        )),
        _ => Err(syn::Error::new_spanned(
            field,
            "an Event field takes only one of #[label], #[context], #[observation]",
        )),
    }
}

fn validate_event_log_field(log: LogSpec, kind: FieldKind, ident: &Ident) -> syn::Result<()> {
    if ident == "message" {
        return Err(syn::Error::new_spanned(
            ident,
            "`message` is reserved for the event message; pick another field name",
        ));
    }
    if log != LogSpec::Off
        && matches!(kind, FieldKind::Label | FieldKind::Context)
        && is_event_log_reserved_field(&ident.to_string())
    {
        return Err(syn::Error::new_spanned(
            ident,
            format!(
                "`{ident}` is reserved by Event-generated logs or the log formatter; choose a \
                 domain-specific field name"
            ),
        ));
    }
    Ok(())
}

fn expand_event(input: DeriveInput) -> syn::Result<TokenStream> {
    let struct_ident = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "Event structs must be concrete (no generics or lifetimes): declare the event with \
             owned fields",
        ));
    }

    let args = parse_event_args(&input)?;

    let event_name = args.event_name.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(&input.ident, "#[event(...)] requires event_name = \"...\"")
    })?;
    if let Err(error) = validate_event_name(&event_name.value()) {
        return Err(syn::Error::new_spanned(event_name, error));
    }
    let component = args.component.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(&input.ident, "#[event(...)] requires component = \"...\"")
    })?;

    let metric_name = match (args.metric, args.metric_name.as_ref()) {
        (MetricSpec::None, Some(metric_name)) => {
            return Err(syn::Error::new_spanned(
                metric_name,
                "metric_name is only valid when metric is counter or histogram",
            ));
        }
        (MetricSpec::None, None) => None,
        (_, Some(metric_name)) => Some(metric_name),
        (_, None) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "metric_name = \"...\" is required when metric is counter or histogram",
            ));
        }
    };
    if args.metric_name_unchecked && metric_name.is_none() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "metric_name_unchecked is only valid for a metric-backed Event",
        ));
    }

    // The metric name in the attribute is the exposed name, verbatim, so a
    // dashboard greps straight back to this line. Validate the conventions
    // unless the site is migrating a grandfathered pre-standard name.
    let mut histogram_unit: Option<&'static str> = None;
    if args.metric == MetricSpec::Histogram
        && let Some(metric_name) = metric_name
    {
        let metric_name_value = metric_name.value();
        histogram_unit = UNIT_SUFFIXES
            .iter()
            .find(|(suffix, _)| metric_name_value.ends_with(suffix))
            .map(|(_, unit)| *unit);
    }
    if !args.metric_name_unchecked
        && let Some(metric_name) = metric_name
    {
        let metric_name_value = metric_name.value();
        if !metric_name_value.starts_with("carbide_") {
            return Err(syn::Error::new_spanned(
                metric_name,
                "metric names use the `carbide_` prefix (use metric_name_unchecked only to \
                 keep a grandfathered pre-standard name)",
            ));
        }
        match args.metric {
            MetricSpec::Counter => {
                if !metric_name_value.ends_with("_total") {
                    return Err(syn::Error::new_spanned(
                        metric_name,
                        "counter names end in `_total` (Prometheus convention)",
                    ));
                }
                // The OpenTelemetry instrument name must not carry `_total`
                // itself: the Prometheus exporter appends it, so a name that
                // still ends in `_total` after one is stripped ships a doubled
                // `_total_total` series (the #3431 footgun).
                if metric_name_value
                    .strip_suffix("_total")
                    .is_some_and(|base| base.ends_with("_total"))
                {
                    return Err(syn::Error::new_spanned(
                        metric_name,
                        "counter name ends in `_total_total`: the Prometheus exporter appends the \
                         `_total` suffix, so the instrument name must carry only one. Drop a \
                         `_total` (use metric_name_unchecked only to keep a grandfathered doubled name)",
                    ));
                }
            }
            MetricSpec::Histogram if histogram_unit.is_none() => {
                return Err(syn::Error::new_spanned(
                    metric_name,
                    "histogram names end in their unit: one of `_seconds`, `_milliseconds`, \
                     `_microseconds`, `_bytes`",
                ));
            }
            _ => {}
        }
        if let Some(unit) = &args.unit {
            return Err(syn::Error::new_spanned(
                unit,
                "`unit` is only for metric_name_unchecked histograms; a standard histogram \
                 name already declares its unit as the suffix",
            ));
        }
    }
    if let Some(unit) = &args.unit
        && args.metric != MetricSpec::Histogram
    {
        return Err(syn::Error::new_spanned(
            unit,
            "`unit` is only valid for histogram metrics",
        ));
    }
    if let Some(describe) = &args.describe
        && args.metric == MetricSpec::None
    {
        return Err(syn::Error::new_spanned(
            describe,
            "`describe` documents a metric (the Prometheus HELP text); this event has \
             metric = none",
        ));
    }
    // A counter's `describe` is its Prometheus HELP text and the row the
    // `core_metrics.md` catalogue records, so a counter must document itself,
    // and the tech-writer house rule is that the text opens with "Number of ".
    // `describe_unchecked` is the escape hatch for a grandfathered describe --
    // legacy phrasings, or the "Total number of ..." on a metric_name_unchecked
    // counter -- mirroring `metric_name_unchecked` for names.
    if args.metric == MetricSpec::Counter && !args.describe_unchecked {
        match &args.describe {
            None => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "a counter must document itself: add describe = \"Number of ...\" (its \
                     Prometheus HELP text, and the core_metrics.md catalogue row). Use \
                     describe_unchecked to keep a grandfathered counter's describe",
                ));
            }
            Some(describe) if !describe.value().starts_with("Number of ") => {
                return Err(syn::Error::new_spanned(
                    describe,
                    "a counter's describe opens with \"Number of ...\" (the tech-writer house \
                     rule). Use describe_unchecked to keep a grandfathered describe",
                ));
            }
            Some(_) => {}
        }
    }
    let unit_value: String = match (&args.unit, histogram_unit) {
        (Some(explicit), _) => explicit.value(),
        (None, Some(from_suffix)) => from_suffix.to_string(),
        (None, None) => String::new(),
    };
    if args.metric == MetricSpec::Histogram && unit_value.is_empty() {
        return Err(syn::Error::new_spanned(
            metric_name.expect("histogram metric name was required above"),
            "a metric_name_unchecked histogram without a recognized suffix needs an explicit \
             unit = \"...\"",
        ));
    }

    if args.message.is_none() && args.log != LogSpec::Off {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "message = \"...\" is required when the event logs (or set log = off for a \
             metric-only event)",
        ));
    }
    if args.log == LogSpec::Off && args.metric == MetricSpec::None {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "an event with log = off and metric = none emits nothing; declare at least one side",
        ));
    }

    // Classify the fields.
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "Event can only be derived for structs",
        ));
    };
    let fields: Vec<&Field> = match &data.fields {
        Fields::Named(named) => named.named.iter().collect(),
        Fields::Unit => Vec::new(),
        Fields::Unnamed(_) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "Event structs use named fields (or none)",
            ));
        }
    };

    let mut labels: Vec<&Ident> = Vec::new();
    let mut contexts: Vec<&Ident> = Vec::new();
    let mut observations: Vec<&Ident> = Vec::new();
    for field in fields {
        let ident = field.ident.as_ref().expect("named field");
        let field_kind = classify_field(field)?;
        validate_event_log_field(args.log, field_kind, ident)?;
        match field_kind {
            FieldKind::Label => labels.push(ident),
            FieldKind::Context => contexts.push(ident),
            FieldKind::Observation => observations.push(ident),
        }
    }

    match (args.metric, observations.len()) {
        (MetricSpec::Histogram, 1) => {}
        (MetricSpec::Histogram, _) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "a histogram event needs exactly one #[observation] field",
            ));
        }
        (_, 0) => {}
        (_, _) => {
            return Err(syn::Error::new_spanned(
                observations[0],
                "#[observation] requires metric = histogram",
            ));
        }
    }

    // The pieces of the generated impl.
    let n_labels = labels.len();
    let label_names: Vec<String> = labels.iter().map(|i| i.to_string()).collect();
    let context_names: Vec<String> = contexts.iter().map(|i| i.to_string()).collect();

    // `log = dynamic` keeps the trait's nominal LOG and routes the decision
    // through the hand-implemented `DynamicLog` -- per-instance levels (count
    // everything, log only failures).
    let log_items = match args.log {
        LogSpec::Dynamic => quote! {
            fn log_at(&self) -> ::carbide_instrument::LogAt {
                ::carbide_instrument::DynamicLog::log_at(self)
            }
        },
        LogSpec::Off => log_const_item(quote! { ::carbide_instrument::LogAt::Off }),
        LogSpec::Error => log_const_item(level_const(quote! { ERROR })),
        LogSpec::Warn => log_const_item(level_const(quote! { WARN })),
        LogSpec::Info => log_const_item(level_const(quote! { INFO })),
        LogSpec::Debug => log_const_item(level_const(quote! { DEBUG })),
        LogSpec::Trace => log_const_item(level_const(quote! { TRACE })),
    };
    let metric_const = match args.metric {
        MetricSpec::Counter => quote! { ::carbide_instrument::MetricKind::Counter },
        MetricSpec::Histogram => {
            quote! { ::carbide_instrument::MetricKind::Histogram { unit: #unit_value } }
        }
        MetricSpec::None => quote! { ::carbide_instrument::MetricKind::None },
    };
    let metric_name_const = match metric_name {
        Some(metric_name) => quote! { ::std::option::Option::Some(#metric_name) },
        None => quote! { ::std::option::Option::None },
    };
    let message_value = args.message.as_ref().map(LitStr::value).unwrap_or_default();
    let describe_value = args
        .describe
        .as_ref()
        .map(LitStr::value)
        .unwrap_or_default();

    let observation_fn = observations.first().map(|obs| {
        quote! {
            fn observation(&self) -> f64 {
                ::carbide_instrument::Observation::observe_as(&self.#obs, #unit_value)
            }
        }
    });

    // One tracing::event! per level: the macro needs a const level and static
    // field names, so the dispatch is generated here rather than written by hand.
    let mut log_fields = vec![quote! { event_name = #event_name }];
    if let Some(metric_name) = metric_name {
        log_fields.push(quote! { metric_name = #metric_name });
    }
    log_fields.extend(labels.iter().map(|ident| {
        quote! {
            #ident = ::carbide_instrument::LabelValue::label_value(&self.#ident).as_str()
        }
    }));
    log_fields.extend(
        contexts
            .iter()
            .map(|ident| quote! { #ident = %self.#ident }),
    );
    let log_arm = |level: proc_macro2::TokenStream| {
        quote! {
            ::carbide_instrument::__private::tracing::event!(
                name: #event_name,
                ::carbide_instrument::__private::tracing::Level::#level,
                #(#log_fields,)*
                "{}",
                __message
            )
        }
    };
    let (arm_error, arm_warn, arm_info, arm_debug, arm_trace) = (
        log_arm(quote! { ERROR }),
        log_arm(quote! { WARN }),
        log_arm(quote! { INFO }),
        log_arm(quote! { DEBUG }),
        log_arm(quote! { TRACE }),
    );
    let log_fn = if args.log == LogSpec::Off {
        quote! {
            fn __log(&self, _level: ::carbide_instrument::__private::tracing::Level) {}
        }
    } else {
        quote! {
            fn __log(&self, level: ::carbide_instrument::__private::tracing::Level) {
                let __message = ::carbide_instrument::Event::message(self);
                if level == ::carbide_instrument::__private::tracing::Level::ERROR {
                    #arm_error;
                } else if level == ::carbide_instrument::__private::tracing::Level::WARN {
                    #arm_warn;
                } else if level == ::carbide_instrument::__private::tracing::Level::INFO {
                    #arm_info;
                } else if level == ::carbide_instrument::__private::tracing::Level::DEBUG {
                    #arm_debug;
                } else {
                    #arm_trace;
                }
            }
        }
    };

    Ok(quote! {
        impl ::carbide_instrument::Event for #struct_ident {
            const EVENT_NAME: &'static str = #event_name;
            const METRIC_NAME: ::std::option::Option<&'static str> = #metric_name_const;
            const COMPONENT: &'static str = #component;
            const DESCRIBE: &'static str = #describe_value;
            #log_items
            const METRIC: ::carbide_instrument::MetricKind = #metric_const;
            type Labels = [::carbide_instrument::__private::opentelemetry::KeyValue; #n_labels];

            fn message(&self) -> &'static str {
                #message_value
            }

            fn labels(&self) -> Self::Labels {
                [
                    #(
                        ::carbide_instrument::__private::opentelemetry::KeyValue::new(
                            #label_names,
                            ::carbide_instrument::LabelValue::label_value(&self.#labels),
                        ),
                    )*
                ]
            }

            fn context(&self) -> ::std::vec::Vec<::carbide_instrument::__private::opentelemetry::KeyValue> {
                ::std::vec![
                    #(
                        ::carbide_instrument::__private::opentelemetry::KeyValue::new(
                            #context_names,
                            ::std::string::ToString::to_string(&self.#contexts),
                        ),
                    )*
                ]
            }

            #observation_fn
            #log_fn

            fn __instrument(&self) -> &'static ::carbide_instrument::__private::CachedInstrument {
                static INSTRUMENT: ::std::sync::OnceLock<
                    ::carbide_instrument::__private::CachedInstrument,
                > = ::std::sync::OnceLock::new();
                INSTRUMENT.get_or_init(::carbide_instrument::__private::new_instrument::<Self>)
            }
        }
    }
    .into())
}

fn log_const_item(value: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! { const LOG: ::carbide_instrument::LogAt = #value; }
}

fn level_const(level: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        ::carbide_instrument::LogAt::Level(
            ::carbide_instrument::__private::tracing::Level::#level,
        )
    }
}

/// `PowerControl` -> `power_control`, `Rms` -> `rms`, `DHCPServer` -> `dhcp_server`.
fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_lower = i > 0 && chars[i - 1].is_lowercase();
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if i > 0 && (prev_lower || next_lower) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(*c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proc_macro2::Span;
    use syn::{DeriveInput, Ident};

    use super::{FieldKind, LogSpec, expand_event, snake_case, validate_event_log_field};

    fn expansion_error(source: &str) -> String {
        let input: DeriveInput = syn::parse_str(source).expect("valid derive input");
        expand_event(input)
            .expect_err("input should be rejected")
            .to_string()
    }

    #[test]
    fn snake_case_variants() {
        assert_eq!(snake_case("Rms"), "rms");
        assert_eq!(snake_case("PowerControl"), "power_control");
        assert_eq!(snake_case("DHCPServer"), "dhcp_server");
        assert_eq!(snake_case("Ok"), "ok");
        assert_eq!(snake_case("NoDpu"), "no_dpu");
        assert_eq!(snake_case("A"), "a");
    }

    #[test]
    fn event_identity_diagnostics_are_specific() {
        struct Case {
            scenario: &'static str,
            source: &'static str,
            expected: &'static str,
        }

        for Case {
            scenario,
            source,
            expected,
        } in [
            Case {
                scenario: "event name is required",
                source: r#"#[event(component = "demo", message = "demo")] struct Demo {}"#,
                expected: "requires event_name",
            },
            Case {
                scenario: "event name follows the shared grammar",
                source: r#"#[event(event_name = "demo.started", component = "demo", message = "demo")] struct Demo {}"#,
                expected: "ASCII lower_snake_case",
            },
            Case {
                scenario: "metric-backed event needs a metric name",
                source: r#"#[event(event_name = "demo", component = "demo", log = off, metric = counter)] struct Demo {}"#,
                expected: "metric_name = \"...\" is required",
            },
            Case {
                scenario: "log-only event rejects a metric name",
                source: r#"#[event(event_name = "demo", metric_name = "carbide_demo_total", component = "demo", message = "demo")] struct Demo {}"#,
                expected: "metric_name is only valid",
            },
            Case {
                scenario: "legacy name explains the split",
                source: r#"#[event(name = "carbide_demo_total", component = "demo", log = off, metric = counter)] struct Demo {}"#,
                expected: "has been split into `event_name` and `metric_name`",
            },
            Case {
                scenario: "unchecked escape hatch is metric-specific",
                source: r#"#[event(event_name = "demo", metric_name = "demo", component = "demo", log = off, metric = counter, name_unchecked)] struct Demo {}"#,
                expected: "renamed to `metric_name_unchecked`",
            },
            Case {
                scenario: "event name is declared once",
                source: r#"#[event(event_name = "first", event_name = "second", component = "demo", message = "demo")] struct Demo {}"#,
                expected: "duplicate `event_name`",
            },
            Case {
                scenario: "metric name is declared once",
                source: r#"#[event(event_name = "demo", metric_name = "carbide_first_total", metric_name = "carbide_second_total", component = "demo", log = off, metric = counter)] struct Demo {}"#,
                expected: "duplicate `metric_name`",
            },
        ] {
            let error = expansion_error(source);
            assert!(
                error.contains(expected),
                "{scenario}: expected `{expected}` in `{error}`"
            );
        }
    }

    #[test]
    fn reserved_fields_apply_only_to_the_log_surface() {
        for field_name in carbide_observability_schema::EVENT_LOG_RESERVED_FIELDS {
            let ident = Ident::new(field_name, Span::call_site());
            if *field_name == "message" {
                for kind in [FieldKind::Label, FieldKind::Context, FieldKind::Observation] {
                    assert!(validate_event_log_field(LogSpec::Info, kind, &ident).is_err());
                    assert!(validate_event_log_field(LogSpec::Off, kind, &ident).is_err());
                }
                continue;
            }
            for kind in [FieldKind::Label, FieldKind::Context] {
                assert!(validate_event_log_field(LogSpec::Info, kind, &ident).is_err());
                assert!(validate_event_log_field(LogSpec::Dynamic, kind, &ident).is_err());
                assert!(validate_event_log_field(LogSpec::Off, kind, &ident).is_ok());
            }
            assert!(
                validate_event_log_field(LogSpec::Info, FieldKind::Observation, &ident).is_ok()
            );
        }

        let machine_id = Ident::new("machine_id", Span::call_site());
        assert!(validate_event_log_field(LogSpec::Info, FieldKind::Context, &machine_id).is_ok());
    }
}
