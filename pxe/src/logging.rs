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

use std::collections::BTreeMap;

use rocket::log::private::info;
use rocket::{
    fairing::{Fairing, Info, Kind},
    Request, Response,
};

/// Logs details about each handled request
#[derive(Debug, Default)]
pub struct RequestLogger;

#[rocket::async_trait]
impl Fairing for RequestLogger {
    fn info(&self) -> Info {
        Info {
            name: "Request Logger",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
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
        if let Some(cl) = request.headers().get_one("Host") {
            props.insert("request_headers_host", cl.to_string());
        }
        if let Some(cl) = request.headers().get_one("Content-Length") {
            props.insert("request_headers_content-length", cl.to_string());
        }
        if let Some(xff) = request.headers().get_one("X-Forwarded-For") {
            props.insert("request_headers_x-forwarded-for", xff.to_string());
        }
        if let Some(xff) = request.headers().get_one("User-Agent") {
            props.insert("request_headers_user-agent", xff.to_string());
        }

        props.insert("response_status", response.status().code.to_string());
        props.insert(
            "response_body_size",
            response.body().preset_size().unwrap_or(0).to_string(),
        );

        props.insert(
            "remote_ip",
            request
                .remote()
                .map(|r| r.ip())
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into())
                .to_string(),
        );
        props.insert(
            "remote_port",
            request.remote().map(|r| r.port()).unwrap_or(0).to_string(),
        );

        let formatted = render_logfmt(&props);
        info!("{formatted}");
    }
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
