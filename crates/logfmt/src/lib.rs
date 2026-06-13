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

use std::any::TypeId;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::Arc;

use tracing::field::{self, Field, Visit};
use tracing::span::{self, Attributes};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Construct a new `LogFmtLayer`
pub fn layer<S>() -> LogFmtLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    LogFmtLayer {
        _registry: PhantomData,
        make_writer: Arc::new(|| Box::new(std::io::stdout())),
        emit_span_logs: true,
        write_end_time: false,
        event_fields: Vec::new(),
    }
}

/// A span attribute surfaced on event and `level=SPAN` lines.
///
/// On each line the rendered value is, in precedence order: the value the line's
/// own span set for `name`; else the value inherited from a parent span; else the
/// configured default, if any; else the field is omitted. So a field built with
/// [`EventField::with_default`] renders on every line, and one built with
/// [`EventField::new`] renders only where a span set or inherited it.
pub struct EventField {
    name: String,
    default: Option<String>,
}

impl EventField {
    /// Surfaced only when a span sets or inherits it (no fallback).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default: None,
        }
    }

    /// Surfaced on every line, falling back to `default` when no span set it.
    pub fn with_default(name: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default: Some(default.into()),
        }
    }
}

/// A Layer which emits `Span` events and `Span` attributes in logfmt syntax
///
/// For spans the layer will emit a log line starting with `level=SPAN`.
/// For events log lines starting with the log level (e.g. `level:INFO`) will be
/// emitted.
///
/// If the emission of Span logs should be prevented, a special attribute `logfmt.suppress`
/// can be set to `true` in the span.
pub struct LogFmtLayer<S> {
    _registry: std::marker::PhantomData<S>,
    make_writer: Arc<dyn Fn() -> Box<dyn Write> + Send + Sync>,
    emit_span_logs: bool,
    write_end_time: bool,
    /// Span attributes surfaced on event and span lines, each with an optional
    /// fallback. See [`EventField`]. Set via `with_event_fields`.
    event_fields: Vec<EventField>,
}

impl<S> LogFmtLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    /// Sets a custom writer for events
    pub fn with_writer(self, make_writer: Arc<dyn Fn() -> Box<dyn Write> + Send + Sync>) -> Self {
        Self {
            make_writer,
            ..self
        }
    }

    /// Whether log events for the Span should be enabled
    pub fn with_span_logs(self, emit_span_logs: bool) -> Self {
        Self {
            emit_span_logs,
            ..self
        }
    }

    /// Whether to write a timing_end_time field in spans
    pub fn with_end_time(self, write_end_time: bool) -> Self {
        Self {
            write_end_time,
            ..self
        }
    }

    /// Surface span attributes on event and `level=SPAN` lines. Each [`EventField`]
    /// renders with its span's own value, else an inherited parent value, else its
    /// default (if any). Calling this replaces the field set (it assigns, it does
    /// not append); duplicate names are dropped (the first wins) so a name is never
    /// emitted twice.
    pub fn with_event_fields(self, fields: impl IntoIterator<Item = EventField>) -> Self {
        let mut seen = std::collections::HashSet::new();
        Self {
            event_fields: fields
                .into_iter()
                .filter(|field| seen.insert(field.name.clone()))
                .collect(),
            ..self
        }
    }

    /// Iterate the names of every configured event field. Used to decide which of
    /// a span's attributes are inherited by its child spans.
    fn configured_field_names(&self) -> impl Iterator<Item = &str> {
        self.event_fields.iter().map(|field| field.name.as_str())
    }

    /// Resolve every configured event field for a line from a span's
    /// `resolved_event_fields` (its own or inherited value), applying each field's
    /// fallback. A field with a default always yields a value; one without is
    /// included only when the span set or inherited it.
    fn resolve_event_fields(
        &self,
        resolved: Option<&BTreeMap<String, String>>,
    ) -> Vec<(String, String)> {
        self.event_fields
            .iter()
            .filter_map(|field| {
                let value = resolved
                    .and_then(|fields| fields.get(&field.name))
                    .cloned()
                    .or_else(|| field.default.clone());
                value.map(|value| (field.name.clone(), value))
            })
            .collect()
    }
}

struct Timing {
    start_time: chrono::DateTime<chrono::Utc>,
    start_time_monotonic: std::time::Instant,
    busy_ns: i64,
    idle_ns: i64,
    last: std::time::Instant,
}

impl Timing {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            busy_ns: 0,
            idle_ns: 0,
            last: now,
            start_time: chrono::Utc::now(),
            start_time_monotonic: now,
        }
    }
}

/// Extension data that is used by the LogFmt Span
struct LogFmtData {
    /// Timing data for the Span
    timing: Timing,
    /// Whether emitting a Span event should be suppressed
    suppressed: bool,
    /// Formatted Span attributes
    /// This is a BTreeMap to guarantee order when formatting
    attributes: BTreeMap<String, String>,
    /// The resolved value of each configured event field for this span (one entry
    /// per `EventField` set on the layer that this span or an ancestor set). Kept
    /// separate from `attributes` because it also holds values inherited from
    /// ancestor spans, which the span never recorded itself.
    ///
    /// Computed when the span is created (`on_new_span`): this span's own
    /// attribute if it set one, otherwise the value inherited from its parent
    /// span. Refreshed in `on_record` if the span sets a value later. Event and
    /// span lines read this map directly. A name is absent when neither this span
    /// nor any of its parent spans set it; the configured default (or omission) is
    /// applied at write time.
    ///
    /// Inheritance is captured at child-creation time: a parent that sets a field
    /// (via `record`) after a child span already exists does not propagate to that
    /// child.
    resolved_event_fields: BTreeMap<String, String>,
}

impl LogFmtData {
    pub fn new() -> Self {
        Self {
            timing: Timing::new(),
            suppressed: false,
            attributes: BTreeMap::new(),
            resolved_event_fields: BTreeMap::new(),
        }
    }

    pub fn update_attribute(&mut self, field: &Field, value: String) {
        // Note that this doesn't use the `.entry()` API to avoid unnecessary
        // allocations for `.to_string()` if the entry does already exist
        match self.attributes.get_mut(field.name()) {
            Some(entry) => {
                *entry = value;
            }
            None => {
                self.attributes.insert(field.name().to_string(), value);
            }
        }
    }
}

impl<S> Layer<S> for LogFmtLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let mut data = LogFmtData::new();
        let mut visitor = SpanAttributeVisitor { data: &mut data };
        attrs.record(&mut visitor);

        // Resolve every configured field's value now, when the span is
        // created, so log lines can read it directly.
        //
        // Resolve the parent span before locking the new span's extensions.
        // `attrs.parent()` gives an explicit parent (`span!(parent: ..)`); when
        // absent and the span is not a root, the parent is the contextual current
        // span. Copying the parent's already-resolved `resolved_event_fields` (a
        // small map — only the configured fields) is what lets a field set on a
        // parent span be inherited here.
        let parent = if let Some(parent_id) = attrs.parent() {
            ctx.span(parent_id)
        } else if attrs.is_root() {
            None
        } else {
            ctx.lookup_current()
        };
        let parent_resolved = parent.as_ref().map(|p| {
            p.extensions()
                .get::<LogFmtData>()
                .map(|d| d.resolved_event_fields.clone())
                .unwrap_or_default()
        });

        for name in self.configured_field_names() {
            if let Some(value) = data.attributes.get(name) {
                // This span set the field itself -> its own value wins.
                data.resolved_event_fields
                    .insert(name.to_string(), value.clone());
            } else if let Some(value) = parent_resolved.as_ref().and_then(|fields| fields.get(name))
            {
                // Inherit the parent's already-resolved value.
                data.resolved_event_fields
                    .insert(name.to_string(), value.clone());
            }
            // Otherwise leave it unset; the default (or omission) is applied at
            // write time.
        }

        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        extensions.insert(data);
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();

        if let Some(data) = extensions.get_mut::<LogFmtData>() {
            let now = std::time::Instant::now();
            data.timing.idle_ns +=
                (now.saturating_duration_since(data.timing.last)).as_nanos() as i64;
            data.timing.last = now;
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();

        if let Some(data) = extensions.get_mut::<LogFmtData>() {
            let now = std::time::Instant::now();
            data.timing.busy_ns +=
                (now.saturating_duration_since(data.timing.last)).as_nanos() as i64;
            data.timing.last = now;
        }
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        if let Some(data) = extensions.get_mut::<LogFmtData>() {
            values.record(&mut SpanAttributeVisitor { data });

            // A value recorded after span creation (e.g. a field declared
            // `tracing::field::Empty` and filled in via `span.record`) must update
            // the span's resolved value. A span's own value always wins over an
            // inherited one, so re-sync each configured field that now has a
            // concrete attribute value.
            for name in self.configured_field_names() {
                if let Some(value) = data.attributes.get(name).cloned() {
                    data.resolved_event_fields.insert(name.to_string(), value);
                }
            }
        }
    }

    fn on_follows_from(&self, _id: &span::Id, _follows: &span::Id, _ctx: Context<S>) {}

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let current_span = ctx.lookup_current();

        // Resolve the event fields and read `span_id` under a single extensions
        // borrow (no extra clone of the span's resolved map). Outside any span the
        // fields fall back to their defaults (or are omitted) and there is no
        // `span_id`.
        let (event_fields, span_id) = match current_span.as_ref() {
            Some(span) => {
                let ext = span.extensions();
                let data = ext
                    .get::<LogFmtData>()
                    .expect("Unable to find LogFmtData in extensions; this is a bug");
                let fields = self.resolve_event_fields(Some(&data.resolved_event_fields));
                let span_id = data.attributes.get("span_id").cloned();
                (fields, span_id)
            }
            None => (self.resolve_event_fields(None), None),
        };

        /// This formatting subfunction exists so that we can use the ? operator
        /// on write! results
        fn write_event_data(
            event: &Event<'_>,
            out: &mut Vec<u8>,
            event_fields: &[(String, String)],
            span_id: Option<&str>,
        ) -> Result<(), std::io::Error> {
            write!(out, "level={} ", event.metadata().level())?;

            // Configured event fields (the span's own or inherited value, else a
            // default) are emitted right after `level=`, so every line carries
            // them — including events emitted outside any span.
            for (name, value) in event_fields {
                write!(out, "{} ", kvp(name, value))?;
            }

            // span_id correlates the event with the span it was logged in.
            if let Some(span_id) = span_id {
                write!(out, "{} ", kvp("span_id", span_id))?;
            }

            let mut visitor = FieldVisitor {
                message: None,
                fields: Vec::with_capacity(event.metadata().fields().len()),
            };
            event.record(&mut visitor);

            if let Some(message) = &visitor.message {
                write!(out, "{} ", kvp("msg", message))?;
            }
            visitor.fields.sort();
            for s in visitor.fields {
                write!(out, "{s} ")?;
            }
            writeln!(
                out,
                r#"location="{}:{}""#,
                event.metadata().file().unwrap_or_default(),
                event.metadata().line().unwrap_or_default()
            )?;

            Ok(())
        }

        // A temporary format buffer is used because accessing stdout can be expensive
        // The format buffer is kept around as a threadlocal variable to reduce allocations
        FORMAT_BUFFER.with(|fbuf| {
            let format_buffer: &mut Vec<u8> = &mut fbuf.borrow_mut();
            if write_event_data(event, format_buffer, &event_fields, span_id.as_deref()).is_ok() {
                let mut writer = (self.make_writer)();
                let _ = writer.write_all(format_buffer);
            }
            clear_format_buffer(format_buffer);
        });
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("Span not found, this is a bug");

        let mut extensions = span.extensions_mut();

        let Some(mut data) = extensions.remove::<LogFmtData>() else {
            return;
        };

        if !self.emit_span_logs {
            // Only return after the extension data is removed. We still need the
            // data around in order to carry the span_id around
            return;
        }

        // Release the extension lock
        drop(extensions);

        if data.suppressed {
            return;
        }

        // Resolve from this span's own resolved values.
        let event_fields = self.resolve_event_fields(Some(&data.resolved_event_fields));

        data.attributes.insert(
            "timing_start_time".to_string(),
            format!("{:?}", data.timing.start_time),
        );
        if self.write_end_time {
            let end_time = chrono::Utc::now();
            data.attributes
                .insert("timing_end_time".to_string(), format!("{end_time:?}"));
        }

        // We use the time when the span was exited the last time to calculate elapsed_us
        // That prevents the time to look high in case any other piece of code held a reference to the span.
        let elapsed = data
            .timing
            .last
            .checked_duration_since(data.timing.start_time_monotonic)
            .unwrap_or_default();
        data.attributes.insert(
            "timing_elapsed_us".to_string(),
            elapsed.as_micros().to_string(),
        );
        data.attributes.insert(
            "timing_busy_ns".to_string(),
            data.timing.busy_ns.to_string(),
        );
        data.attributes.insert(
            "timing_idle_ns".to_string(),
            data.timing.idle_ns.to_string(),
        );

        // Emit span attributes as event

        /// This formatting subfunction exists so that we can use the ? operator
        /// on write! results
        fn write_span_data(
            span_metadata: &tracing::Metadata,
            mut data: LogFmtData,
            out: &mut Vec<u8>,
            event_fields: &[(String, String)],
        ) -> Result<(), std::io::Error> {
            write!(out, "level=SPAN")?;

            // Resolved event fields are emitted right after `level=SPAN`, mirroring
            // event lines. Remove each from the span's own attributes first so it
            // is not emitted twice (a span may set the attribute directly).
            for (name, value) in event_fields {
                data.attributes.remove(name);
                write!(out, " {}", kvp(name, value))?;
            }

            // Start writing the span_id and span_name for consistency
            if let Some(value) = data.attributes.remove("span_id") {
                write!(out, " {}", kvp("span_id", value))?;
            }

            let span_name = span_metadata.name();
            write!(out, " {}", kvp("span_name", span_name))?;

            for (key, value) in data.attributes.iter() {
                write!(out, " {}", kvp(key, value))?;
            }

            out.push(b'\n');

            Ok(())
        }

        // A temporary format buffer is used because accessing stdout can be expensive
        // The format buffer is kept around as a threadlocal variable to reduce allocations
        FORMAT_BUFFER.with(|fbuf| {
            let format_buffer: &mut Vec<u8> = &mut fbuf.borrow_mut();
            if let Ok(()) = write_span_data(span.metadata(), data, format_buffer, &event_fields) {
                let mut writer = (self.make_writer)();
                let _ = writer.write_all(format_buffer);
            }
            clear_format_buffer(format_buffer);
        });
    }

    // SAFETY: this is safe because the `WithContext` function pointer is valid
    // for the lifetime of `&self`.
    unsafe fn downcast_raw(&self, id: TypeId) -> Option<*const ()> {
        match id {
            id if id == TypeId::of::<Self>() => Some(self as *const _ as *const ()),
            _ => None,
        }
    }
}

enum EscapedKeyName<'a> {
    /// The string didn't need escaping. We don't need an extra allocation
    Original(&'a str),
    /// The string needed escaping. We need a copy
    Escaped(String),
}

impl std::fmt::Display for EscapedKeyName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscapedKeyName::Original(s) => s.fmt(f),
            EscapedKeyName::Escaped(s) => s.fmt(f),
        }
    }
}

/// Escapes key names. Fields with `.` in their name require conversion to `_`
fn escape_key_name(key: &str) -> EscapedKeyName<'_> {
    // TODO: Potentially escape more key characters
    if key.contains('.') {
        EscapedKeyName::Escaped(key.replace('.', "_"))
    } else {
        EscapedKeyName::Original(key)
    }
}

/// A helper to write key-value pairs
///
/// Values are escaped in quotes if required
struct Kvp<K, V> {
    key: K,
    value: V,
}

fn kvp<K, V>(key: K, value: V) -> Kvp<K, V> {
    Kvp { key, value }
}

impl<K: AsRef<str>, V: AsRef<str>> std::fmt::Display for Kvp<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let escaped_key = escape_key_name(self.key.as_ref());

        if self
            .value
            .as_ref()
            .as_bytes()
            .iter()
            .any(|c| *c <= b' ' || matches!(*c, b'=' | b'"'))
        {
            write!(
                f,
                r#"{}="{}""#,
                escaped_key,
                self.value.as_ref().escape_debug()
            )?;
        } else {
            write!(f, "{}={}", escaped_key, self.value.as_ref().escape_debug())?;
        }

        Ok(())
    }
}

struct SpanAttributeVisitor<'a> {
    data: &'a mut LogFmtData,
}

impl field::Visit for SpanAttributeVisitor<'_> {
    fn record_bool(&mut self, field: &field::Field, value: bool) {
        match field.name() {
            "logfmt.suppress" => {
                self.data.suppressed = value;
            }
            _ => self.data.update_attribute(field, value.to_string()),
        }
    }

    fn record_f64(&mut self, field: &field::Field, value: f64) {
        self.data.update_attribute(field, value.to_string());
    }

    fn record_i64(&mut self, field: &field::Field, value: i64) {
        self.data.update_attribute(field, value.to_string());
    }

    fn record_str(&mut self, field: &field::Field, value: &str) {
        self.data.update_attribute(field, value.to_string());
    }

    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        self.data.update_attribute(field, value);
    }

    fn record_error(&mut self, field: &field::Field, value: &(dyn std::error::Error + 'static)) {
        self.data.update_attribute(field, value.to_string());
    }
}

/// A visitor for recording fields in span events
pub struct FieldVisitor {
    pub message: Option<String>,
    pub fields: Vec<String>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.push(format!("{}", kvp(field.name(), value)));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
            return;
        }
        self.record_str(field, &format!("{value:?}"));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push(format!("{}={value}", escape_key_name(field.name())));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_str(field, &value.to_string());
    }
}

thread_local! {
    static FORMAT_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn clear_format_buffer(buf: &mut Vec<u8>) {
    const MAX_FORMAT_BUFFER_CAPACITY: usize = 1024;
    buf.clear();
    if buf.capacity() > MAX_FORMAT_BUFFER_CAPACITY {
        buf.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tracing::Level;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    use super::*;

    #[derive(Clone)]
    struct TestWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl TestWriter {
        pub fn new() -> Self {
            Self {
                buf: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn text(&self) -> String {
            let guard = self.buf.lock().unwrap();
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self.buf.lock().unwrap();
            guard.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_logfmt_layer() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer().with_writer(Arc::new(move || Box::new(cloned_writer.clone())));

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(tracing::Level::WARN,
            "test_span",
            span_id = "s1234",
            fval.initial = 1.00,
            fval.unset = tracing::field::Empty,
            fval.updated = 1.00,
            ival.initial = 0,
            ival.unset = tracing::field::Empty,
            ival.updated = 0,
            sval.inital = "a",
            sval.unset = tracing::field::Empty,
            sval.updated = "b",
            bval.inital = false,
            bval.unset = tracing::field::Empty,
            bval.updated = false,
            dval.initial = ?std::time::Duration::from_secs(1),
            dval.unset = tracing::field::Empty,
            dval.updated = ?std::time::Duration::from_secs(1),
            eval.initial = &std::io::Error::new(std::io::ErrorKind::Unsupported, "ab") as &dyn std::error::Error,
            eval.unset = tracing::field::Empty,
            eval.updated = &std::io::Error::new(std::io::ErrorKind::Unsupported, "ad") as &dyn std::error::Error,
        );

        let _entered = span.enter();
        tracing::event!(
            name: "asdf",
            target: "logfmt::layer",
            Level::INFO,
            summary = "Summary1",
            bool.value = false,
            i64.value = -3,
            f64.value = "-2.0",
            str.value = "Hello",
            str.escaped_value = "Hello World",
            debug.value = ?std::time::Duration::from_secs(111),
            error.value = &std::io::Error::new(std::io::ErrorKind::Unsupported, "abc") as &dyn std::error::Error);
        tracing::error!("as expected");

        span.record("bval.unset", true);
        span.record("bval.updated", true);
        span.record("fval.unset", 2.2);
        span.record("fval.updated", 3.3);
        span.record("ival.unset", 9);
        span.record("ival.updated", 3);
        span.record("sval.unset", "c");
        span.record("sval.updated", "d e");
        span.record(
            "dval.unset",
            field::debug(std::time::Duration::from_secs(2)),
        );
        span.record(
            "dval.updated",
            field::debug(std::time::Duration::from_secs(3)),
        );
        span.record(
            "eval.unset",
            &std::io::Error::new(std::io::ErrorKind::Unsupported, "bb") as &dyn std::error::Error,
        );
        span.record(
            "eval.updated",
            &std::io::Error::new(std::io::ErrorKind::Unsupported, "cc") as &dyn std::error::Error,
        );

        // Wait a bit before exiting the span. The busy time should be logged as part of timing_elapsed_us
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(_entered);

        // Before closing the span, wait a bit more. This time should not be logged.
        // It purely exists because something else still holds a reference to the span - even in case it might not be useful
        std::thread::sleep(std::time::Duration::from_millis(500));
        drop(span);

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            3,
            "Expected 3 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(lines[0].starts_with(r#"level=INFO span_id=s1234 bool_value=false debug_value=111s error_value=abc f64_value=-2.0 i64_value=-3 str_escaped_value="Hello World" str_value=Hello summary=Summary1 location=""#), "Line is: {}", lines[0]);
        assert!(
            lines[1].starts_with(r#"level=ERROR span_id=s1234 msg="as expected" location=""#),
            "Line is: {}",
            lines[1]
        );
        assert!(lines[2].starts_with(r#"level=SPAN span_id=s1234 span_name=test_span bval_inital=false bval_unset=true bval_updated=true dval_initial=1s dval_unset=2s dval_updated=3s eval_initial=ab eval_unset=bb eval_updated=cc fval_initial=1 fval_unset=2.2 fval_updated=3.3 ival_initial=0 ival_unset=9 ival_updated=3 sval_inital=a sval_unset=c sval_updated="d e" timing_"#), "Line is: {}", lines[2]);
        let elapsed_str_idx = lines[2].find("timing_elapsed_us=").unwrap();
        let elapsed_str = lines[2][elapsed_str_idx..].trim_start_matches("timing_elapsed_us=");
        let elapsed_str_end_idx = elapsed_str.find(' ').unwrap();
        let elapsed_str = &elapsed_str[..elapsed_str_end_idx];
        let elapsed_us: u64 = elapsed_str.parse().unwrap();
        assert!(
            (100_000..400_000).contains(&elapsed_us),
            "Elapsed duration is {elapsed_us}us"
        );
    }

    #[test]
    fn test_span_logs_are_emitted_according_to_log_level() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer().with_writer(Arc::new(move || Box::new(cloned_writer.clone())));

        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .parse_lossy("warn"); // Equals `RUST_LOG=warn`
        let _subscriber = tracing_subscriber::registry()
            .with(layer.with_filter(env_filter))
            .set_default();

        let span = tracing::span!(tracing::Level::INFO, "info_span", span_id = "s1234",);
        let _entered = span.enter();
        tracing::info!("info_event");
        drop(_entered);
        drop(span);

        let span = tracing::span!(tracing::Level::WARN, "warn_span", span_id = "s1234",);
        let _entered = span.enter();
        tracing::warn!("warn_event");
        drop(_entered);
        drop(span);

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            2,
            "Expected 2 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(
            lines[0].starts_with(r#"level=WARN span_id=s1234 msg=warn_event location="#),
            "Line is: {}",
            lines[0]
        );
        assert!(
            lines[1].starts_with(r#"level=SPAN span_id=s1234 span_name=warn_span timing_"#),
            "Line is: {}",
            lines[1]
        );
    }

    #[test]
    fn test_suppress_span_logs() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer().with_writer(Arc::new(move || Box::new(cloned_writer.clone())));

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(tracing::Level::WARN, "a", logfmt.suppress = true,);
        drop(span);

        let span = tracing::span!(tracing::Level::WARN, "b", logfmt.suppress = false,);
        drop(span);

        let span = tracing::span!(
            tracing::Level::WARN,
            "c",
            logfmt.suppress = tracing::field::Empty,
        );
        span.record("logfmt.suppress", true);
        drop(span);

        let span = tracing::span!(
            tracing::Level::WARN,
            "d",
            logfmt.suppress = tracing::field::Empty,
        );
        span.record("logfmt.suppress", true);
        span.record("logfmt.suppress", false);
        drop(span);

        let span = tracing::span!(
            tracing::Level::WARN,
            "e",
            logfmt.suppress = tracing::field::Empty,
        );
        span.record("logfmt.suppress", false);
        drop(span);

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            3,
            "Expected 3 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(
            lines[0].starts_with(r#"level=SPAN span_name=b"#),
            "Line is: {}",
            lines[0]
        );
        assert!(
            lines[1].starts_with(r#"level=SPAN span_name=d"#),
            "Line is: {}",
            lines[1]
        );
        assert!(
            lines[2].starts_with(r#"level=SPAN span_name=e"#),
            "Line is: {}",
            lines[2]
        );
    }

    #[test]
    fn test_disable_span_logs() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_span_logs(false);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(tracing::Level::WARN, "test_span", span_id = "s1234",);

        let _entered = span.enter();
        tracing::info!("abc");
        // Write the span event
        drop(_entered);
        drop(span);

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            1,
            "Expected 1 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(
            lines[0].starts_with(r#"level=INFO span_id=s1234 msg=abc location=""#),
            "Line is: {}",
            lines[0]
        );
    }

    #[test]
    fn test_event_outside_of_span() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer().with_writer(Arc::new(move || Box::new(cloned_writer.clone())));

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        tracing::warn!(a = 100, "outside_event!");

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            1,
            "Expected 1 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        assert!(
            lines[0].starts_with(r#"level=WARN msg=outside_event! a=100 location=""#),
            "Line is: {}",
            lines[0]
        );
    }

    #[test]
    fn test_default_field_on_event_and_span() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(tracing::Level::INFO, "test_span", span_id = "s1234",);
        let _entered = span.enter();
        tracing::info!("inside");
        drop(_entered);
        drop(span);

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(lines.len(), 2, "got {}: {:?}", lines.len(), lines);
        // The default is emitted right after `level=` on both lines.
        assert!(
            lines[0].starts_with(r#"level=INFO service=service-a span_id=s1234 msg=inside "#),
            "Line is: {}",
            lines[0]
        );
        assert!(
            lines[1]
                .starts_with(r#"level=SPAN service=service-a span_id=s1234 span_name=test_span "#),
            "Line is: {}",
            lines[1]
        );
    }

    #[test]
    fn test_span_value_overrides_default_once() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(
            tracing::Level::INFO,
            "outer",
            span_id = "s1",
            service = "service-b",
        );
        let _entered = span.enter();
        tracing::info!("inside");
        drop(_entered);
        drop(span);

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(lines.len(), 2, "got {}: {:?}", lines.len(), lines);
        // The span value overrides the default, and `service` appears once.
        assert!(
            lines[0].starts_with(r#"level=INFO service=service-b span_id=s1 msg=inside "#),
            "Line is: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains("service-a"),
            "default leaked: {}",
            lines[0]
        );
        assert_eq!(
            lines[0].matches("service=").count(),
            1,
            "duplicate service key: {}",
            lines[0]
        );
        assert!(
            lines[1].starts_with(r#"level=SPAN service=service-b span_id=s1 span_name=outer "#),
            "Line is: {}",
            lines[1]
        );
        assert_eq!(
            lines[1].matches("service=").count(),
            1,
            "duplicate service key: {}",
            lines[1]
        );
    }

    #[test]
    fn test_default_field_inherited_by_nested_span() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        // Root span sets `service`; the nested child span does not.
        let root = tracing::span!(
            tracing::Level::INFO,
            "outer",
            span_id = "root",
            service = "service-b",
        );
        let _root_entered = root.enter();
        let child = tracing::span!(tracing::Level::INFO, "inner", span_id = "child");
        let _child_entered = child.enter();
        tracing::warn!("inner_event");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        // The event fires in the child span, which set no `service`; it must
        // inherit `service-b` from the root span.
        let event_line = lines
            .iter()
            .find(|l| l.contains("msg=inner_event"))
            .expect("event line not found");
        assert!(
            event_line.contains("service=service-b"),
            "nested event did not inherit service: {event_line}"
        );
        assert!(
            !event_line.contains("service=service-a"),
            "nested event fell back to default: {event_line}"
        );
    }

    #[test]
    fn test_no_field_when_unset() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer().with_writer(Arc::new(move || Box::new(cloned_writer.clone())));

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        tracing::warn!("e");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        // With no default and no span override, no `service` field is emitted,
        // guaranteeing byte-identical output for the existing snapshot tests.
        assert!(
            lines[0].starts_with(r#"level=WARN msg=e "#),
            "Line is: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains("service="),
            "unexpected service: {}",
            lines[0]
        );
    }

    #[test]
    fn test_extra_field_on_event_line() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::new("request_id")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(
            tracing::Level::INFO,
            "test_span",
            span_id = "s1234",
            request_id = "req-abc-123",
        );

        let _entered = span.enter();
        tracing::info!("event inside span with request_id");
        drop(_entered);
        drop(span);

        // Check the written data
        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        assert_eq!(
            lines.len(),
            2,
            "Expected 2 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        // Event should include both span_id and request_id
        assert!(
            lines[0].starts_with(r#"level=INFO request_id=req-abc-123 span_id=s1234 msg="event inside span with request_id" location=""#),
            "Line is: {}",
            lines[0]
        );
    }

    #[test]
    fn test_extra_field_inherited_from_parent_span() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::new("request_id")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        // Parent sets `request_id`; the nested child does not -> the child's event
        // inherits it from the parent span.
        let root = tracing::span!(
            tracing::Level::INFO,
            "outer",
            span_id = "root",
            request_id = "req-1",
        );
        let _root = root.enter();
        let child = tracing::span!(tracing::Level::INFO, "inner", span_id = "child");
        let _child = child.enter();
        tracing::info!("inner_event");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let event_line = lines
            .iter()
            .find(|l| l.contains("msg=inner_event"))
            .expect("event line not found");
        assert!(
            event_line.contains("request_id=req-1"),
            "nested event did not inherit request_id: {event_line}"
        );
    }

    #[test]
    fn test_extra_field_child_value_overrides_parent() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::new("request_id")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        // Both parent and child set `request_id` -> the child's own value wins
        // over the inherited parent value; a parent never replaces a child's value.
        let root = tracing::span!(
            tracing::Level::INFO,
            "outer",
            span_id = "root",
            request_id = "req-parent",
        );
        let _root = root.enter();
        let child = tracing::span!(
            tracing::Level::INFO,
            "inner",
            span_id = "child",
            request_id = "req-child",
        );
        let _child = child.enter();
        tracing::info!("inner_event");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let event_line = lines
            .iter()
            .find(|l| l.contains("msg=inner_event"))
            .expect("event line not found");
        assert!(
            event_line.contains("request_id=req-child"),
            "child's own request_id should win: {event_line}"
        );
        assert!(
            !event_line.contains("req-parent"),
            "parent value leaked: {event_line}"
        );
    }

    #[test]
    fn test_extra_field_on_span_line() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::new("request_id")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        // A plain extra field is emitted on span-close lines too (not just event
        // lines): the span that sets it carries it on its own close line, and a
        // nested span that doesn't set it inherits it onto its close line.
        let root = tracing::span!(
            tracing::Level::INFO,
            "outer",
            span_id = "root",
            request_id = "req-1",
        );
        let _root = root.enter();
        let child = tracing::span!(tracing::Level::INFO, "inner", span_id = "child");
        drop(child); // child's SPAN line
        drop(_root);
        drop(root); // outer's SPAN line

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let child_span = lines
            .iter()
            .find(|l| l.contains("span_name=inner"))
            .expect("child span line not found");
        let outer_span = lines
            .iter()
            .find(|l| l.contains("span_name=outer"))
            .expect("outer span line not found");
        // Inherited onto the child's close line, present on the outer's, once each.
        assert!(
            child_span.contains("request_id=req-1"),
            "child span line missing inherited request_id: {child_span}"
        );
        assert_eq!(
            child_span.matches("request_id=").count(),
            1,
            "duplicate request_id on child span line: {child_span}"
        );
        assert!(
            outer_span.contains("request_id=req-1"),
            "outer span line missing request_id: {outer_span}"
        );
        assert_eq!(
            outer_span.matches("request_id=").count(),
            1,
            "duplicate request_id on outer span line: {outer_span}"
        );
    }

    // --- event-field inheritance edge cases ---

    #[test]
    fn test_explicit_parent_inheritance() {
        // Inheritance must follow an explicit `parent:` link, not just the
        // contextual current span. Here the child is created with an explicit
        // parent that is NOT entered, so contextual lookup would miss it.
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let parent = tracing::span!(
            tracing::Level::INFO,
            "parent",
            span_id = "p",
            service = "service-b",
        );
        // Note: parent is never entered. The child names it explicitly.
        let child = tracing::span!(parent: &parent, tracing::Level::INFO, "child", span_id = "c");
        let _entered = child.enter();
        tracing::info!("explicit_parent_event");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let event_line = lines
            .iter()
            .find(|l| l.contains("msg=explicit_parent_event"))
            .expect("event line not found");
        assert!(
            event_line.contains("service=service-b"),
            "explicit parent value not inherited: {event_line}"
        );
        assert!(
            !event_line.contains("service-a"),
            "fell back to default instead of inheriting explicit parent: {event_line}"
        );
    }

    #[test]
    fn test_empty_field_recorded_after_creation_overrides_inherited() {
        // A child declares the field as `Empty` (so it has no own value at
        // creation and inherits the parent's resolved value), then fills it in
        // via `span.record`. `on_record` must refresh the resolved value so the
        // span's own value wins over the inherited one.
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let root = tracing::span!(
            tracing::Level::INFO,
            "root",
            span_id = "root",
            service = "parent-comp",
        );
        let _root = root.enter();
        let child = tracing::span!(
            tracing::Level::INFO,
            "child",
            span_id = "child",
            service = tracing::field::Empty,
        );
        let _child = child.enter();
        // Before record: should inherit `parent-comp`.
        tracing::info!("before_record");
        child.record("service", "child-comp");
        // After record: the span's own value wins.
        tracing::info!("after_record");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let before = lines
            .iter()
            .find(|l| l.contains("msg=before_record"))
            .expect("before line not found");
        let after = lines
            .iter()
            .find(|l| l.contains("msg=after_record"))
            .expect("after line not found");
        assert!(
            before.contains("service=parent-comp"),
            "child with Empty field did not inherit parent before record: {before}"
        );
        assert!(
            after.contains("service=child-comp"),
            "on_record did not refresh resolved value: {after}"
        );
    }

    #[test]
    fn test_deeply_nested_inheritance() {
        // Only the outermost span sets the field; deeply nested descendants must
        // still see it. Each level copies its parent's already-resolved value, so
        // the value propagates down through every nested span.
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields([EventField::with_default("service", "service-a")]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let s1 = tracing::span!(tracing::Level::INFO, "s1", service = "deep-comp");
        let _e1 = s1.enter();
        let s2 = tracing::span!(tracing::Level::INFO, "s2");
        let _e2 = s2.enter();
        let s3 = tracing::span!(tracing::Level::INFO, "s3");
        let _e3 = s3.enter();
        let s4 = tracing::span!(tracing::Level::INFO, "s4");
        let _e4 = s4.enter();
        tracing::info!("deep_event");

        let lines: Vec<String> = writer.text().lines().map(ToString::to_string).collect();
        let event_line = lines
            .iter()
            .find(|l| l.contains("msg=deep_event"))
            .expect("event line not found");
        assert!(
            event_line.contains("service=deep-comp"),
            "deeply nested span did not inherit service: {event_line}"
        );
    }
}
