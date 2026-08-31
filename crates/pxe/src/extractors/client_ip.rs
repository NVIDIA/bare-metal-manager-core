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

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum_client_ip::ClientIp;
use ipnet::IpNet;

use crate::common::AppState;
use crate::rpc_error::PxeRequestError;

pub(super) async fn extract(
    parts: &mut Parts,
    state: &AppState,
) -> Result<IpAddr, PxeRequestError> {
    let direct_ip = ClientIp::from_request_parts(parts, state)
        .await
        .map_err(PxeRequestError::MissingIp)?
        .0;

    resolve_client_ip(
        direct_ip,
        &parts.headers,
        &state.runtime_config.trusted_proxy_cidrs,
    )
}

fn resolve_client_ip(
    direct_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> Result<IpAddr, PxeRequestError> {
    if !is_trusted(direct_ip, trusted_proxies) {
        return Ok(direct_ip);
    }

    let mut forwarded_values = headers.get_all("x-forwarded-for").iter();
    let Some(forwarded_for) = forwarded_values.next() else {
        return Ok(direct_ip);
    };
    if forwarded_values.next().is_some() {
        return Err(PxeRequestError::InvalidProxyHeader(
            "multiple X-Forwarded-For header fields".to_string(),
        ));
    }
    let forwarded_for = forwarded_for
        .to_str()
        .map_err(|error| PxeRequestError::InvalidProxyHeader(error.to_string()))?;

    select_forwarded_ip(direct_ip, forwarded_for, trusted_proxies)
}

fn select_forwarded_ip(
    direct_ip: IpAddr,
    forwarded_for: &str,
    trusted_proxies: &[IpNet],
) -> Result<IpAddr, PxeRequestError> {
    let addresses = forwarded_for
        .split(',')
        .map(str::trim)
        .map(|value| {
            value.parse::<IpAddr>().map_err(|error| {
                PxeRequestError::InvalidProxyHeader(format!(
                    "X-Forwarded-For contains {value:?}: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    addresses
        .into_iter()
        .rev()
        .find(|address| !is_trusted(*address, trusted_proxies))
        .ok_or_else(|| {
            PxeRequestError::InvalidProxyHeader(format!(
                "X-Forwarded-For has no client address before trusted proxy {direct_ip}"
            ))
        })
}

fn is_trusted(address: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies
        .iter()
        .any(|network| network.contains(&address))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::*;

    #[derive(Debug)]
    struct ResolveCase {
        direct_ip: &'static str,
        forwarded_for: &'static [&'static [u8]],
        trusted_proxy_cidrs: &'static [&'static str],
    }

    fn resolve_case(case: ResolveCase) -> Result<IpAddr, ()> {
        let direct_ip = case.direct_ip.parse().unwrap();
        let mut headers = HeaderMap::new();
        for value in case.forwarded_for {
            headers.append("x-forwarded-for", HeaderValue::from_bytes(value).unwrap());
        }
        let trusted_proxies = case
            .trusted_proxy_cidrs
            .iter()
            .map(|value| value.parse().unwrap())
            .collect::<Vec<_>>();

        resolve_client_ip(direct_ip, &headers, &trusted_proxies).map_err(drop)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn resolves_client_ip_across_trust_boundary() {
        scenarios!(resolve_case:
            "direct peer is not trusted" {
                ResolveCase {
                    direct_ip: "192.0.2.10",
                    forwarded_for: &[],
                    trusted_proxy_cidrs: &[],
                } => Yields(ip("192.0.2.10")),
                ResolveCase {
                    direct_ip: "192.0.2.10",
                    forwarded_for: &[b"198.51.100.20"],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Yields(ip("192.0.2.10")),
                ResolveCase {
                    direct_ip: "192.0.2.10",
                    forwarded_for: &[&[0xff]],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Yields(ip("192.0.2.10")),
            }

            "direct peer is trusted" {
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Yields(ip("127.0.0.1")),
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[b"198.51.100.20, 192.0.2.30, 10.1.2.3"],
                    trusted_proxy_cidrs: &["127.0.0.0/8", "10.0.0.0/8"],
                } => Yields(ip("192.0.2.30")),
            }

            "trusted forwarding is malformed" {
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[b"not-an-ip, 198.51.100.20"],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Fails,
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[&[0xff]],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Fails,
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[b"10.1.2.3"],
                    trusted_proxy_cidrs: &["127.0.0.0/8", "10.0.0.0/8"],
                } => Fails,
                ResolveCase {
                    direct_ip: "127.0.0.1",
                    forwarded_for: &[b"198.51.100.20", b"192.0.2.30"],
                    trusted_proxy_cidrs: &["127.0.0.0/8"],
                } => Fails,
            }
        );
    }
}
