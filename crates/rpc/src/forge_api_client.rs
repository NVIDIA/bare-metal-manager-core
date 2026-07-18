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
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use nonempty::NonEmpty;
use tonic::Status;

use crate::forge_tls_client::{
    ApiConfig, ForgeClientConfig, ForgeClientT, ForgeTlsClient, RetryConfig,
};
pub use crate::protos::forge_api_client::ForgeApiClient;

pub const EXPECTED_SWITCH_UPDATE_MASK_HEADER: &str = "x-nico-expected-switch-update-mask";

pub mod expected_switch_update_field {
    pub const BMC_USERNAME: &str = "bmc_username";
    pub const BMC_PASSWORD: &str = "bmc_password";
    pub const SWITCH_SERIAL_NUMBER: &str = "switch_serial_number";
    pub const NVOS_MAC_ADDRESSES: &str = "nvos_mac_addresses";
    pub const NVOS_USERNAME: &str = "nvos_username";
    pub const NVOS_PASSWORD: &str = "nvos_password";
    pub const METADATA_NAME: &str = "metadata.name";
    pub const METADATA_DESCRIPTION: &str = "metadata.description";
    pub const METADATA_LABELS: &str = "metadata.labels";
    pub const RACK_ID: &str = "rack_id";
    pub const BMC_IP_ADDRESS: &str = "bmc_ip_address";
    pub const NVOS_IP_ADDRESS: &str = "nvos_ip_address";
    pub const BMC_RETAIN_CREDENTIALS: &str = "bmc_retain_credentials";

    pub const ALL: &[&str] = &[
        BMC_USERNAME,
        BMC_PASSWORD,
        SWITCH_SERIAL_NUMBER,
        NVOS_MAC_ADDRESSES,
        NVOS_USERNAME,
        NVOS_PASSWORD,
        METADATA_NAME,
        METADATA_DESCRIPTION,
        METADATA_LABELS,
        RACK_ID,
        BMC_IP_ADDRESS,
        NVOS_IP_ADDRESS,
        BMC_RETAIN_CREDENTIALS,
    ];
}

/// Builds the sparse-update field mask represented by `switch`.
pub fn expected_switch_update_mask(switch: &crate::protos::forge::ExpectedSwitch) -> String {
    use expected_switch_update_field as field;

    let mut fields = Vec::new();

    if !switch.bmc_username.is_empty() || !switch.bmc_password.is_empty() {
        fields.extend([field::BMC_USERNAME, field::BMC_PASSWORD]);
    }

    if !switch.switch_serial_number.is_empty() {
        fields.push(field::SWITCH_SERIAL_NUMBER);
    }

    if !switch.nvos_mac_addresses.is_empty() {
        fields.push(field::NVOS_MAC_ADDRESSES);
    }

    if switch.nvos_username.is_some() || switch.nvos_password.is_some() {
        fields.extend([field::NVOS_USERNAME, field::NVOS_PASSWORD]);
    }

    if let Some(metadata) = &switch.metadata {
        if !metadata.name.is_empty() {
            fields.push(field::METADATA_NAME);
        }

        if !metadata.description.is_empty() {
            fields.push(field::METADATA_DESCRIPTION);
        }

        if !metadata.labels.is_empty() {
            fields.push(field::METADATA_LABELS);
        }
    }

    if switch.rack_id.is_some() {
        fields.push(field::RACK_ID);
    }

    if !switch.bmc_ip_address.is_empty() {
        fields.push(field::BMC_IP_ADDRESS);
    }

    if switch.nvos_ip_address.is_some() {
        fields.push(field::NVOS_IP_ADDRESS);
    }

    if switch.bmc_retain_credentials.is_some() {
        fields.push(field::BMC_RETAIN_CREDENTIALS);
    }

    fields.join(",")
}

impl ForgeApiClient {
    pub fn new(api_config: &ApiConfig<'_>) -> Self {
        Self::build(ForgeTlsConnectionProvider {
            urls: NonEmpty::from((
                api_config.url.to_string(),
                api_config.additional_urls.to_vec(),
            )),
            client_config: api_config.client_config.clone(),
            retry_config: api_config.retry_config,
            last_connection_index: 0.into(),
            fail_over_on: FailOverOn::ConnectionError,
        })
    }

    pub fn new_with_failover_behavior(
        api_config: &ApiConfig<'_>,
        fail_over_on: FailOverOn,
    ) -> Self {
        Self::build(ForgeTlsConnectionProvider {
            urls: NonEmpty::from((
                api_config.url.to_string(),
                api_config.additional_urls.to_vec(),
            )),
            client_config: api_config.client_config.clone(),
            retry_config: api_config.retry_config,
            last_connection_index: 0.into(),
            fail_over_on,
        })
    }

    /// Applies the named `ExpectedSwitch` fields without replacing omitted fields.
    pub async fn patch_expected_switch(
        &self,
        switch: crate::protos::forge::ExpectedSwitch,
        update_mask: &str,
    ) -> Result<(), Status> {
        let update_mask = update_mask
            .parse()
            .map_err(|error| Status::invalid_argument(format!("invalid update mask: {error}")))?;

        let mut request = tonic::Request::new(switch);
        request
            .metadata_mut()
            .insert(EXPECTED_SWITCH_UPDATE_MASK_HEADER, update_mask);

        self.connection()
            .await?
            .update_expected_switch(request)
            .await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ForgeTlsConnectionProvider {
    pub urls: NonEmpty<String>,
    pub client_config: ForgeClientConfig,
    pub retry_config: RetryConfig,
    pub fail_over_on: FailOverOn,
    pub last_connection_index: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
/// Determines when ForgeTlsConnectionProvider should select the next server in the list, if
/// configured for multiple carbide-api servers.
pub enum FailOverOn {
    /// Fail over whenever there is a failure connecting to carbide-api. Note that fail-back is not
    /// (yet) supported.
    ConnectionError,
    /// Select a new carbide-api instance on every call to carbide-api. This is currently only
    /// needed by tests, where we intentionally want to vary the connection to emulate what a load
    /// balancer would do.
    EveryApiCall,
}

impl ForgeTlsConnectionProvider {
    fn current_endpoint_url(&self) -> &str {
        // SAFETY: last_connection_index is always modulo urls.len()
        self.urls
            .get(self.last_connection_index.load(Ordering::SeqCst))
            .unwrap()
    }

    fn next_endpoint_url(&self) -> &str {
        let connection_index = self
            .last_connection_index
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current_index| {
                Some((current_index + 1) % self.urls.len())
            })
            .unwrap(); // SAFETY: we always return Some(), so this will always succeed.
        // SAFETY: connection_index is always modulo urls.len()
        self.urls.get(connection_index).unwrap()
    }
}

#[async_trait::async_trait]
impl tonic_client_wrapper::ConnectionProvider<ForgeClientT> for ForgeTlsConnectionProvider {
    async fn provide_connection(&self) -> Result<ForgeClientT, Status> {
        let mut url = if self.urls.len() <= 1 {
            self.urls.first()
        } else {
            match self.fail_over_on {
                FailOverOn::ConnectionError => self.current_endpoint_url(),
                FailOverOn::EveryApiCall => self.next_endpoint_url(),
            }
        };

        let mut retries = 0;
        loop {
            match ForgeTlsClient::retry_build(
                &ApiConfig::new(url, &self.client_config).with_retry_config(RetryConfig {
                    // We do our own retry counting
                    retries: 1,
                    interval: self.retry_config.interval,
                }),
            )
            .await
            .map_err(Into::into)
            {
                Ok(client) => return Ok(client),
                Err(e) => {
                    retries += 1;
                    if retries > self.retry_config.retries {
                        return Err(e);
                    }
                    url = self.next_endpoint_url();
                }
            }
        }
    }

    async fn connection_is_stale(&self, last_connected: SystemTime) -> bool {
        if matches!(self.fail_over_on, FailOverOn::EveryApiCall) {
            // We can switch between API instances on every API call by just always considering the
            // connection to be stale.
            return true;
        }

        if let Some(ref client_cert) = self.client_config.client_cert {
            if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                if mtime > last_connected {
                    let old_cert_date = DateTime::<Utc>::from(last_connected);
                    let new_cert_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        cert_path = &client_cert.cert_path,
                        %old_cert_date,
                        %new_cert_date,
                        "ForgeApiClient: Reconnecting to pick up newer client certificate"
                    );
                    true
                } else {
                    false
                }
            } else if let Ok(mtime) = fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
            {
                // Just in case the cert and key are created some amount of time apart and we
                // last constructed a client with the new cert but the old key...
                if mtime > last_connected {
                    let old_key_date = DateTime::<Utc>::from(last_connected);
                    let new_key_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        key_path = &client_cert.key_path,
                        %old_key_date,
                        %new_key_date,
                        "ForgeApiClient: Reconnecting to pick up newer client key"
                    );
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn connection_url(&self) -> &str {
        self.current_endpoint_url()
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;
    use crate::protos::forge::ExpectedSwitch;

    #[test]
    fn expected_switch_update_mask_contains_only_provided_fields() {
        check_values(
            [
                Check {
                    scenario: "empty patch",
                    input: ExpectedSwitch::default(),
                    expect: String::new(),
                },
                Check {
                    scenario: "paired credentials",
                    input: ExpectedSwitch {
                        bmc_username: "bmc-admin".to_string(),
                        bmc_password: "bmc-password".to_string(),
                        nvos_username: Some("nvos-admin".to_string()),
                        nvos_password: Some("nvos-password".to_string()),
                        ..Default::default()
                    },
                    expect: "bmc_username,bmc_password,nvos_username,nvos_password".to_string(),
                },
                Check {
                    scenario: "switch endpoint fields",
                    input: ExpectedSwitch {
                        switch_serial_number: "serial".to_string(),
                        nvos_mac_addresses: vec!["00:11:22:33:44:55".to_string()],
                        bmc_ip_address: "192.0.2.1".to_string(),
                        nvos_ip_address: Some("192.0.2.2".to_string()),
                        bmc_retain_credentials: Some(true),
                        ..Default::default()
                    },
                    expect: "switch_serial_number,nvos_mac_addresses,bmc_ip_address,nvos_ip_address,bmc_retain_credentials".to_string(),
                },
            ],
            |switch| expected_switch_update_mask(&switch),
        );
    }
}
