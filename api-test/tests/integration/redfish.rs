/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use async_trait::async_trait;
use carbide::redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};
use forge_secrets::credentials::{CredentialProvider, Credentials, TestCredentialProvider};
use http::HeaderName;
use libredfish::{Endpoint, Redfish};
use machine_a_tron::bmc_mock_wrapper::BmcMockAddressRegistry;
use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

pub struct MachineATronBackedRedfishClientPool {
    inner: libredfish::RedfishClientPool,
    bmc_address_registry: BmcMockAddressRegistry,
}

impl MachineATronBackedRedfishClientPool {
    pub fn new(
        bmc_address_registry: BmcMockAddressRegistry,
    ) -> MachineATronBackedRedfishClientPool {
        let rf_pool = libredfish::RedfishClientPool::builder().build().unwrap();
        MachineATronBackedRedfishClientPool {
            inner: rf_pool,
            bmc_address_registry,
        }
    }
}

#[async_trait]
impl RedfishClientPool for MachineATronBackedRedfishClientPool {
    /// Create a client, but instead of connecting to the requested ip:port, look for the machine
    /// (or DPU) in the list of machine-a-tron mocks that has that particular IP, and connect to its
    /// BMC mock instead (which may be listening on a different port, to avoid allocating IP's in
    /// tests.) If the IP isn't found, or if the bmc-mock isn't listening, return an error.
    async fn create_client_with_custom_headers(
        &self,
        host: &str,
        _port: Option<u16>,
        custom_headers: &[(String, String)],
        _auth: RedfishAuth,
        _initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let Ok(ip_addr) = Ipv4Addr::from_str(host) else {
            tracing::error!("libredfish is attempting to connect to a host via an invalid IP address: {}. Note: hostnames are not supported in mock BMC's.", host);
            return Err(RedfishClientCreationError::NotImplemented);
        };

        let Some(addr) = self
            .bmc_address_registry
            .read()
            .await
            .get(&ip_addr)
            .cloned()
        else {
            tracing::info!("could not create redfish client: BMC mock is not listening for {host}");
            return Err(RedfishClientCreationError::NotImplemented);
        };

        let custom_headers = custom_headers
            .iter()
            .map(|(header_str, value_str)| {
                let header: HeaderName = HeaderName::from_str(header_str)
                    .map_err(RedfishClientCreationError::InvalidHeader)?;
                Ok((header, value_str.clone()))
            })
            .collect::<Result<Vec<(HeaderName, String)>, RedfishClientCreationError>>()?;

        self.inner
            .create_client_with_custom_headers(
                Endpoint {
                    host: addr.ip().to_string(),
                    port: Some(addr.port()),
                    password: None,
                    user: None,
                },
                custom_headers,
            )
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }

    fn credential_provider(&self) -> Arc<dyn CredentialProvider> {
        Arc::new(TestCredentialProvider::new(Credentials::UsernamePassword {
            username: "user".to_string(),
            password: "password".to_string(),
        }))
    }
}
