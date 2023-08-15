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

use async_trait::async_trait;
use futures::future::BoxFuture;
use opentelemetry::{
    sdk::{
        self,
        export::trace::{ExportResult, SpanData, SpanExporter},
    },
    ExportError,
};

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

#[async_trait]
impl<W> SpanExporter for OtelStdoutExporter<W>
where
    W: Write + std::fmt::Debug + Send + 'static,
{
    /// Export spans to stdout
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        for span in batch {
            if self.ignored_spans.contains(&&*span.name) {
                continue;
            }

            let method: String = span
                .attributes
                .get(&opentelemetry_semantic_conventions::trace::RPC_METHOD)
                .map(|value| value.as_str().into_owned())
                .unwrap_or_default();

            // We ignore periodic requests if their outcome is OK
            // If these RPCs fail we keep them around, so that its more obvious
            // for operators that something went wrong
            if span.status == opentelemetry_api::trace::Status::Ok
                && IGNORED_REQUEST_METHODDS.contains(&method.as_str())
            {
                continue;
            }

            writeln!(
                &mut self.writer,
                "Span: {} [ID: {}, Parent: {}, Status: {:?}]",
                span.name,
                span.span_context.span_id(),
                span.parent_span_id,
                span.status
            )
            .unwrap();
            writeln!(&mut self.writer, "Attributes:").unwrap();
            for (k, v) in span.attributes.iter() {
                writeln!(&mut self.writer, "  {}={}", k.as_str(), v.as_str()).unwrap();
            }

            for (k, v) in span.resource.iter() {
                writeln!(&mut self.writer, "  {}={}", k.as_str(), v.as_str()).unwrap();
            }

            if !span.events.is_empty() {
                writeln!(&mut self.writer, "Events:\n").unwrap();
                for ev in span.events.iter() {
                    writeln!(
                        &mut self.writer,
                        "  {:?} {}",
                        chrono::DateTime::<chrono::Utc>::from(ev.timestamp),
                        ev.name
                    )
                    .unwrap();
                    for kv in ev.attributes.iter() {
                        writeln!(
                            &mut self.writer,
                            "    {}={}",
                            kv.key.as_str(),
                            kv.value.as_str()
                        )
                        .unwrap();
                    }
                }
            }
            writeln!(&mut self.writer, "----").unwrap();
        }

        Box::pin(std::future::ready(Ok(())))
    }

    fn shutdown(&mut self) {}

    fn force_flush(
        &mut self,
    ) -> futures::future::BoxFuture<'static, sdk::export::trace::ExportResult> {
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
