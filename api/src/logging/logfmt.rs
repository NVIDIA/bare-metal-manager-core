/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use tracing::{
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::{
    fmt::{format::Writer, FmtContext, FormatEvent, FormatFields, FormattedFields},
    registry::LookupSpan,
};

/// A tracing formatter that outputs in logfmt (key=value) format.
/// The message appears as 'msg'.
pub struct LogFmtFormatter {}

impl<S, N> FormatEvent<S, N> for LogFmtFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    // Required method
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        write!(&mut writer, "level={} ", metadata.level())?;
        if let Some(leaf_span) = ctx.lookup_current() {
            // The other way is to make a Layer
            // in on_new_span look in attributes.values(), get "span_id"
            // make a newtype SpanId, store it span.extensions_mut().insert(SpanId(span_id))
            // then we can get it here like FormattedFields
            let ext = leaf_span.extensions();
            let data = ext
                .get::<FormattedFields<N>>()
                .expect("Unable to find FormattedFields in extensions; this is a bug");
            let span_id = data
                .split_ascii_whitespace()
                .find(|&v| v.starts_with("span_id"));
            if let Some(span_id_formatted) = span_id {
                write!(&mut writer, "{span_id_formatted} ").unwrap();
            }
        }

        let mut visitor = Visitor {
            message: None,
            out: Vec::with_capacity(metadata.fields().len()),
        };
        event.record(&mut visitor);
        if let Some(message) = visitor.message {
            write!(&mut writer, r#"msg="{}" "#, message.escape_debug())?;
        }
        visitor.out.sort();
        for s in visitor.out {
            write!(&mut writer, "{s}")?;
        }
        writeln!(
            &mut writer,
            r#"location="{}:{}""#,
            metadata.file().unwrap_or_default(),
            metadata.line().unwrap_or_default()
        )?;

        Ok(())
    }
}

pub struct Visitor {
    pub message: Option<String>,
    pub out: Vec<String>,
}

impl Visit for Visitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if value
            .as_bytes()
            .iter()
            .any(|c| *c <= b' ' || matches!(*c, b'=' | b'"'))
        {
            self.out
                .push(format!(r#"{}="{}" "#, field.name(), value.escape_debug()));
        } else {
            self.out
                .push(format!("{}={} ", field.name(), value.escape_debug()));
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
            return;
        }
        self.record_str(field, &format!("{:?}", value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.out.push(format!("{}={value} ", field.name()));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_str(field, &value.to_string());
    }
}
