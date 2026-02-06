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
use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;

pub(crate) async fn logger(
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let mut props = BTreeMap::new();
    props.insert("level", "SPAN".to_string());
    props.insert("span_name", "request".to_string());

    props.insert("request_method", request.method().to_string());
    props.insert("request_path", request.uri().path().to_string());
    props.insert(
        "request_query",
        request
            .uri()
            .query()
            .map(|q| q.to_string())
            .unwrap_or_default(),
    );
    if let Some(host) = request.headers().get("Host").and_then(|h| h.to_str().ok()) {
        props.insert("request_headers_host", host.to_string());
    }
    if let Some(content_length) = request
        .headers()
        .get("Content-Length")
        .and_then(|h| h.to_str().ok())
    {
        props.insert("request_headers_content-length", content_length.to_string());
    }
    if let Some(x_forwarded_for) = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
    {
        props.insert(
            "request_headers_x-forwarded-for",
            x_forwarded_for.to_string(),
        );
    }
    if let Some(user_agent) = request
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
    {
        props.insert("request_headers_user-agent", user_agent.to_string());
    }

    let response = next.run(request).await;

    props.insert("response_status", response.status().as_str().to_string());
    if let Some(content_length) = response
        .headers()
        .get("Content-Length")
        .and_then(|h| h.to_str().ok())
    {
        props.insert(
            "response_headers_content-length",
            content_length.to_string(),
        );
    }

    props.insert("remote_ip", socket_addr.ip().to_string());
    props.insert("remote_port", socket_addr.port().to_string());

    let formatted = render_logfmt(&props);
    println!("{formatted}");

    response
}

/// Renders a list of key-value pairs into a logfmt string
fn render_logfmt(props: &BTreeMap<&'static str, String>) -> String {
    let mut msg = String::new();

    for (key, value) in props {
        if !msg.is_empty() {
            msg.push(' ');
        }
        msg += key;
        msg.push('=');
        let needs_quotes = value.is_empty()
            || value
                .as_bytes()
                .iter()
                .any(|c| *c <= b' ' || matches!(*c, b'=' | b'"'));

        if needs_quotes {
            msg.push('"');
        }

        msg.push_str(&value.escape_debug().to_string());

        if needs_quotes {
            msg.push('"');
        }
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logfmt() {
        let mut props = BTreeMap::new();
        props.insert("method", "GET".to_string());
        props.insert("path", "/boot".to_string());
        props.insert("remote_ip", "127.0.0.1".to_string());
        assert_eq!(
            render_logfmt(&props),
            "method=GET path=/boot remote_ip=127.0.0.1"
        );

        props.insert("z", "with whitespace".to_string());
        props.insert("e", "".to_string());
        assert_eq!(
            render_logfmt(&props),
            "e=\"\" method=GET path=/boot remote_ip=127.0.0.1 z=\"with whitespace\""
        );
    }
}
