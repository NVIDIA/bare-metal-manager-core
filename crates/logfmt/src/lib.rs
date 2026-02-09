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
use tracing_subscriber::registry::{LookupSpan, SpanRef};

/// Construct a new `LogFmtLayer`
pub fn layer<S>() -> LogFmtLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    LogFmtLayer {
        _registry: PhantomData,
        make_writer: Arc::new(|| Box::new(std::io::stdout())),
        emit_span_logs: true,
        extra_event_fields: Vec::new(),
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
    extra_event_fields: Vec<String>,
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

    /// Add extra span attribute keys to emit in event logs
    pub fn with_event_fields(self, extra_event_fields: Vec<String>) -> Self {
        Self {
            extra_event_fields,
            ..self
        }
    }
}

struct Timing {
    start_time: chrono::DateTime<chrono::Utc>,
    busy_ns: i64,
    idle_ns: i64,
    last: std::time::Instant,
}

impl Timing {
    pub fn new() -> Self {
        Self {
            busy_ns: 0,
            idle_ns: 0,
            last: std::time::Instant::now(),
            start_time: chrono::Utc::now(),
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
}

impl LogFmtData {
    pub fn new() -> Self {
        Self {
            timing: Timing::new(),
            suppressed: false,
            attributes: BTreeMap::new(),
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
        }
    }

    fn on_follows_from(&self, _id: &span::Id, _follows: &span::Id, _ctx: Context<S>) {}

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // If the event doesn't happen in the scope of a Span, we don't log some span data
        let current_span = ctx.lookup_current();

        /// This formatting subfunction exists so that we can use the ? operator
        /// on write! results
        fn write_event_data<'a, R: LookupSpan<'a>>(
            event: &Event<'_>,
            current_span: Option<&SpanRef<'a, R>>,
            out: &mut Vec<u8>,
            extra_event_fields: &[String],
        ) -> Result<(), std::io::Error> {
            write!(out, "level={} ", event.metadata().level())?;

            // TODO: More metadata?

            if let Some(current_span) = current_span {
                // Get the span_id to correlate the event with the actual span
                let ext = current_span.extensions();
                let data = ext
                    .get::<LogFmtData>()
                    .expect("Unable to find LogFmtData in extensions; this is a bug");

                if let Some(span_id) = data.attributes.get("span_id") {
                    write!(out, "{} ", kvp("span_id", span_id))?;
                }
                for key in extra_event_fields {
                    if let Some(value) = data.attributes.get(key) {
                        write!(out, "{} ", kvp(key, value))?;
                    }
                }
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
            if let Ok(()) = write_event_data(
                event,
                current_span.as_ref(),
                format_buffer,
                &self.extra_event_fields,
            ) {
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

        data.attributes.insert(
            "timing_start_time".to_string(),
            format!("{:?}", data.timing.start_time),
        );
        let end_time = chrono::Utc::now();
        data.attributes
            .insert("timing_end_time".to_string(), format!("{end_time:?}"));
        let elapsed = end_time.signed_duration_since(data.timing.start_time);
        data.attributes.insert(
            "timing_elapsed_us".to_string(),
            elapsed.num_microseconds().unwrap_or_default().to_string(),
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
        ) -> Result<(), std::io::Error> {
            write!(out, "level=SPAN")?;

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
            if let Ok(()) = write_span_data(span.metadata(), data, format_buffer) {
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

        // Write the span event
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(_entered);

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
            (100_000..1_000_000).contains(&elapsed_us),
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
    fn test_object_id_in_event_logs() {
        let writer = TestWriter::new();
        let cloned_writer = writer.clone();
        let layer = layer()
            .with_writer(Arc::new(move || Box::new(cloned_writer.clone())))
            .with_event_fields(vec!["object_id".to_string()]);

        let _subscriber = tracing_subscriber::registry().with(layer).set_default();

        let span = tracing::span!(
            tracing::Level::INFO,
            "test_span",
            span_id = "s1234",
            object_id = "machine-abc-123",
        );

        let _entered = span.enter();
        tracing::info!("event inside span with object_id");
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
        // Event should include both span_id and object_id
        assert!(
            lines[0].starts_with(r#"level=INFO span_id=s1234 object_id=machine-abc-123 msg="event inside span with object_id" location=""#),
            "Line is: {}",
            lines[0]
        );
    }
}
