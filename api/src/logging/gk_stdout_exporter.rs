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
    ExportError, Key,
};

const IGNORED_SPANS: &[&str] = &["state_controller_iteration"];

#[derive(Debug)]
pub struct GkStdoutExporter<W: Write> {
    writer: W,
}

impl<W: Write> GkStdoutExporter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

#[async_trait]
impl<W> SpanExporter for GkStdoutExporter<W>
where
    W: Write + std::fmt::Debug + Send + 'static,
{
    /// Export spans to stdout
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        for span in batch {
            if IGNORED_SPANS.contains(&&*span.name) {
                continue;
            }

            let attrs = &span.attributes;
            macro_rules! get {
                ($key:literal) => {
                    attrs
                        .get(&Key::from_static_str($key))
                        .map(|v| v.as_str())
                        .unwrap_or_default()
                };
            }
            let mut msg = format!(
                "{}  SPAN {}/{} {}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ"),
                get!("rpc.service"),
                get!("rpc.method"),
                get!("request"),
            );
            let status = get!("rpc.grpc.status_code");
            if status != "0" {
                // 0 is success grpc success
                msg += &format!(" {} {}", status, get!("rpc.grpc.status_description"));
            }
            writeln!(&mut self.writer, "{}", msg).unwrap();
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
