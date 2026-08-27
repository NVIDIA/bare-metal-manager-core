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

use std::borrow::Cow;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use carbide_instrument::red;
use carbide_secrets::credentials::{CredentialReader, Credentials};
use carbide_utils::HostPortPair;
use carbide_utils::redfish::format_forwarded_host_parameter;
use libredfish::model::service_root::RedfishVendor;
use libredfish::{Endpoint, Redfish};

use crate::libredfish::instrumented::{InstrumentedRedfish, REDFISH_BACKEND};
use crate::libredfish::vendor_selection::ClientMode;
use crate::libredfish::{
    BmcVendorOverrideResolver, RedfishAuth, RedfishClientCreationError, RedfishClientPool,
    VendorSelection,
};

/// Formats a host for the URL authority that `libredfish` constructs internally.
///
/// `libredfish::Endpoint` accepts a host and port separately, but the pinned
/// implementation interpolates them into a URL string. Keep callers' host values
/// bare and add IPv6 brackets only at this external serialization boundary.
fn libredfish_endpoint_host(host: &str) -> Cow<'_, str> {
    if host.parse::<Ipv6Addr>().is_ok() {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
    }
}

pub(super) struct RedfishClientPoolImpl {
    pool: libredfish::RedfishClientPool,
    credential_reader: Arc<dyn CredentialReader>,
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    vendor_override_resolver: Arc<dyn BmcVendorOverrideResolver>,
}

impl RedfishClientPoolImpl {
    pub(super) fn new(
        credential_reader: Arc<dyn CredentialReader>,
        pool: libredfish::RedfishClientPool,
        proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
        vendor_override_resolver: Arc<dyn BmcVendorOverrideResolver>,
    ) -> Self {
        RedfishClientPoolImpl {
            credential_reader,
            pool,
            proxy_address,
            vendor_override_resolver,
        }
    }

    /// The operator pinned vendor for `host`, or `None` for detection.
    /// The single place a resolver failure is handled, and it cannot fail hard.
    async fn pinned_vendor(&self, host: &str) -> Option<RedfishVendor> {
        match self.vendor_override_resolver.vendor_override(host).await {
            Ok(vendor) => vendor,
            Err(error) => {
                // Warn, matching the `nv_redfish` pool. Every BMC client is built
                // through here, so a quieter line would hide a resolver outage.
                tracing::warn!(
                    bmc = %host,
                    %error,
                    "Failed to resolve bmc_vendor_override, using automatic detection"
                );
                None
            }
        }
    }
}

#[async_trait]
impl RedfishClientPool for RedfishClientPoolImpl {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        vendor: VendorSelection,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let original_host = host;

        // Allow globally overriding the bmc port via site-config. We read this on every call to
        // create_client, because self.proxy_address is a dynamic setting.
        let proxy_address = self.proxy_address.load();
        let (host, port, add_custom_header) = match proxy_address.as_ref() {
            // No override
            None => (host, port, false),
            // Override the host and port
            Some(HostPortPair::HostAndPort(h, p)) => (h.as_str(), Some(*p), true),
            // Only override the host
            Some(HostPortPair::HostOnly(h)) => (h.as_str(), port, true),
            // Only override the port
            Some(HostPortPair::PortOnly(p)) => (host, Some(*p), false),
        };

        let (username, password) = match auth {
            RedfishAuth::Anonymous => (None, None), // anonymous login, usually to get service root Vendor info
            RedfishAuth::Direct(username, password) => (Some(username), Some(password)),
            RedfishAuth::Key(credential_key) => {
                let credentials = self
                    .credential_reader
                    .get_credentials(&credential_key)
                    .await?
                    .ok_or_else(|| RedfishClientCreationError::MissingCredentials {
                        key: credential_key.to_key_str().to_string(),
                    })?;

                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => {
                        (Some(username), Some(password))
                    }
                };

                (username, password)
            }
        };

        let endpoint = Endpoint {
            host: libredfish_endpoint_host(host).into_owned(),
            port,
            user: username,
            password,
        };

        let custom_headers = if add_custom_header {
            // If we're overriding the host, inject a header indicating the IP address we were
            // originally going to use, using the HTTP "Forwarded" header:
            // https://datatracker.ietf.org/doc/html/rfc7239

            // Override host only if host value is provided in config.
            vec![(
                http::HeaderName::from_str("forwarded")
                    .map_err(|err| RedfishClientCreationError::InvalidHeader(err.to_string()))?,
                format_forwarded_host_parameter(original_host),
            )]
        } else {
            Vec::default()
        };

        // Resolve the operator pin only for the modes it can apply to. The
        // uninitialized mode returns first, as a vendor breaks factory bootstrap.
        let mode = match vendor {
            VendorSelection::Uninitialized => ClientMode::Uninitialized,
            selection => selection.resolve(self.pinned_vendor(original_host).await),
        };

        // The initializing paths below make HTTP calls of their own, so they
        // are metered like any other Redfish operation.
        let client = match mode {
            // Auto-detect vendor from the service root.
            ClientMode::Detect => red::instrumented(
                REDFISH_BACKEND,
                "create_client",
                self.pool
                    .create_client_with_custom_headers(endpoint, custom_headers),
            )
            .await
            .map_err(RedfishClientCreationError::RedfishError)?,
            // No vendor, so return a standard client making no HTTP calls, as the
            // anonymous probe needs. /Systems answers 401 where auth is required.
            ClientMode::Uninitialized => self
                .pool
                .create_standard_client_with_custom_headers(endpoint, custom_headers)
                .map_err(RedfishClientCreationError::RedfishError)
                .map(|c| c as Box<dyn Redfish>)?,
            ClientMode::Vendor(vendor) => red::instrumented(
                REDFISH_BACKEND,
                "create_client",
                self.pool
                    .create_client_with_vendor(endpoint, vendor, custom_headers),
            )
            .await
            .map_err(RedfishClientCreationError::RedfishError)?,
        };

        // Every client the pool creates goes out decorated, so each Redfish
        // call records the per-operation RED triad no matter the call site.
        Ok(Box::new(InstrumentedRedfish::new(client)))
    }

    fn credential_reader(&self) -> &dyn CredentialReader {
        &*self.credential_reader
    }

    async fn pinned_bmc_vendor(&self, host: &str) -> Option<RedfishVendor> {
        self.pinned_vendor(host).await
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::libredfish_endpoint_host;

    #[test]
    fn endpoint_host_brackets_only_bare_ipv6_literals() {
        value_scenarios!(run = |host| libredfish_endpoint_host(host).into_owned();
            "unchanged hosts" {
                "bmc.example.com" => "bmc.example.com".to_string(),
                "192.0.2.10" => "192.0.2.10".to_string(),
                "[2001:db8::10]" => "[2001:db8::10]".to_string(),
            }

            "bracketed IPv6 host" {
                "2001:db8::10" => "[2001:db8::10]".to_string(),
            }
        );
    }
}
