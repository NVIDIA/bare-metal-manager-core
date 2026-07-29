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

use std::net::IpAddr;

use mac_address::MacAddress;

/// `parse_uri_host_ip` parses an IPv4 literal or a bare/bracketed IPv6 literal.
///
/// `http::Uri::host` retains IPv6 brackets, while other callers can provide
/// bare addresses. Accept both forms here; hostnames return `None`.
pub fn parse_uri_host_ip(host: &str) -> Option<IpAddr> {
    host.parse().ok().or_else(|| {
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .and_then(|host| host.parse().ok())
    })
}

/// Formats the `host` parameter for an HTTP `Forwarded` header.
///
/// RFC 7239 requires an IPv6 host to use brackets inside a quoted string.
/// Hostnames and IPv4 literals retain the existing token form.
pub fn format_forwarded_host_parameter(host: &str) -> String {
    match parse_uri_host_ip(host) {
        Some(IpAddr::V6(host)) => format!("host=\"[{host}]\""),
        _ => format!("host={host}"),
    }
}

/// Data needed to access BMC via Redfish.
///
/// It is regular host, port pair + MAC address that identifies auth
/// key identifier for the access.
pub struct BmcAccessInfo {
    pub host: String,
    pub port: Option<u16>,
    pub mac_address: MacAddress,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::{format_forwarded_host_parameter, parse_uri_host_ip};

    #[test]
    fn uri_host_parser_accepts_bare_and_bracketed_ip_literals() {
        value_scenarios!(run = |host| parse_uri_host_ip(host).map(|ip| ip.to_string());
            "IP literals" {
                "192.0.2.10" => Some("192.0.2.10".to_string()),
                "2001:db8::10" => Some("2001:db8::10".to_string()),
                "[2001:db8::10]" => Some("2001:db8::10".to_string()),
            }

            "hostname" {
                "bmc.example.com" => None,
            }
        );
    }

    #[test]
    fn forwarded_host_parameter_quotes_ipv6_literals() {
        value_scenarios!(run = format_forwarded_host_parameter;
            "token form" {
                "bmc.example.com" => "host=bmc.example.com".to_string(),
                "192.0.2.10" => "host=192.0.2.10".to_string(),
            }

            "quoted IPv6 form" {
                "2001:db8::10" => "host=\"[2001:db8::10]\"".to_string(),
                "[2001:db8::10]" => "host=\"[2001:db8::10]\"".to_string(),
            }
        );
    }
}
