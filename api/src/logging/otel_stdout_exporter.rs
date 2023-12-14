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

//! This module implements an OpenTelemetry exporter which writes
//! OpenTelemetry spans to stdout

use std::io::Write;

use futures::future::BoxFuture;
use opentelemetry::{ExportError, Key};
use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};

#[derive(Debug)]
pub struct OtelStdoutExporter<W: Write> {
    writer: W,
    ignored_spans: &'static [&'static str],
}

impl<W: Write> OtelStdoutExporter<W> {
    /// Creates a new `OtelStdoutExporter`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            ignored_spans: IGNORED_SPANS,
        }
    }
}

const IGNORED_SPANS: &[&str] = &[];

const IGNORED_REQUEST_METHODDS: &[&str] =
    &["GetManagedHostNetworkConfig", "RecordDpuNetworkStatus"];

impl<W> SpanExporter for OtelStdoutExporter<W>
where
    W: Write + std::fmt::Debug + Send + Sync + 'static,
{
    /// Export spans to stdout
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        for span in batch {
            if self.ignored_spans.contains(&&*span.name) {
                continue;
            }

            let method: String = span
                .attributes
                .iter()
                .find(|kvp| kvp.key == opentelemetry_semantic_conventions::trace::RPC_METHOD)
                .map(|kvp| kvp.value.as_str().into_owned())
                .unwrap_or_default();

            // We ignore periodic requests if their outcome is OK
            // If these RPCs fail we keep them around, so that its more obvious
            // for operators that something went wrong
            if span.status == opentelemetry::trace::Status::Ok
                && IGNORED_REQUEST_METHODDS.contains(&method.as_str())
            {
                continue;
            }

            let mut kv = Vec::new();
            for kvp in span.attributes.iter() {
                if kvp.key.as_str() == "span_id" {
                    continue;
                }
                kv.push((
                    kvp.key.as_str().replace('.', "_"),
                    kvp.value.as_str().to_string(),
                ));
            }
            for (k, v) in span.resource.iter() {
                kv.push((k.as_str().replace('.', "_"), v.as_str().to_string()));
            }
            kv.sort();

            write!(&mut self.writer, "level=SPAN ").unwrap();
            let span_id = span
                .attributes
                .iter()
                .find(|kvp| kvp.key == Key::new("span_id"))
                .map(|kvp| &kvp.value);
            if let Some(span_id) = span_id {
                write!(&mut self.writer, r#"span_id="{}" "#, span_id).unwrap();
            }
            write!(
                &mut self.writer,
                r#"span_name={} status="{}" "#,
                &span.name,
                format!("{:?}", span.status).escape_debug()
            )
            .unwrap();

            for (k, v) in kv {
                if v.as_bytes()
                    .iter()
                    .any(|c| *c <= b' ' || matches!(*c, b'=' | b'"'))
                {
                    write!(&mut self.writer, r#"{}="{}" "#, k, v.escape_debug()).unwrap();
                } else {
                    write!(&mut self.writer, "{}={} ", k, v.escape_debug()).unwrap();
                }
            }
            writeln!(&mut self.writer).unwrap();
        }

        Box::pin(std::future::ready(Ok(())))
    }

    fn shutdown(&mut self) {}

    fn force_flush(
        &mut self,
    ) -> futures::future::BoxFuture<'static, opentelemetry_sdk::export::trace::ExportResult> {
        Box::pin(async { Ok(()) })
    }
}

/// Stdout exporter's error
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
struct SpanExporterError(#[from] std::io::Error);

impl ExportError for SpanExporterError {
    fn exporter_name(&self) -> &'static str {
        "stdout"
    }
}
