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

use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use carbide_host_support::registration;
use eyre::Context;
use forge_tls::client_config::ClientCert;
use rand::Rng;

/// Certificates are renewed between in these 2 time intervals
const MIN_CERT_RENEWAL_TIME_SECS: u64 = 5 * 24 * 60 * 60; // 5 days
const MAX_CERT_RENEWAL_TIME_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

const MIN_CERT_RENEWAL_FAILURE_TIME_SECS: u64 = 60; // 1 min
const MAX_CERT_RENEWAL_FAILURE_TIME_SECS: u64 = 5 * 60; // 5min

pub struct ClientCertRenewer {
    cert_renewal_time: std::time::Instant,
    forge_api_server: String,
    client_config: Arc<ForgeClientConfig>,
}

impl ClientCertRenewer {
    pub fn new(forge_api_server: String, client_config: Arc<ForgeClientConfig>) -> Self {
        let cert_renewal_period =
            rand::rng().random_range(MIN_CERT_RENEWAL_TIME_SECS..MAX_CERT_RENEWAL_TIME_SECS);
        let cert_renewal_time = Instant::now().add(Duration::from_secs(cert_renewal_period));

        Self {
            cert_renewal_time,
            forge_api_server,
            client_config,
        }
    }

    /// Renews Client certificates once a certain timeframe has elapsed
    pub async fn renew_certificates_if_necessary(
        &mut self,
        override_client_cert: Option<&ClientCert>,
    ) {
        let now = std::time::Instant::now();
        if now > self.cert_renewal_time {
            let cert_renewal_period = match self.renew_certificates(override_client_cert).await {
                Ok(()) => {
                    rand::rng().random_range(MIN_CERT_RENEWAL_TIME_SECS..MAX_CERT_RENEWAL_TIME_SECS)
                }
                Err(err) => {
                    let cert_renewal_period = rand::rng().random_range(
                        MIN_CERT_RENEWAL_FAILURE_TIME_SECS..MAX_CERT_RENEWAL_FAILURE_TIME_SECS,
                    );
                    tracing::error!(
                        error = format!("{err:#}"),
                        "Failed to renew client certificates. Will retry in {cert_renewal_period}s"
                    );

                    cert_renewal_period
                }
            };
            self.cert_renewal_time = now.add(Duration::from_secs(cert_renewal_period));
        }
    }

    /// Enforces cert renewal on the next renew_certificates_if_necessary call
    pub fn renew_on_next_check(&mut self) {
        self.cert_renewal_time = std::time::Instant::now();
    }

    async fn renew_certificates(
        &mut self,
        override_client_cert: Option<&ClientCert>,
    ) -> Result<(), eyre::Report> {
        tracing::info!("Trying to renew TLS client certificates");
        let mut client = forge_tls_client::ForgeTlsClient::retry_build(&ApiConfig::new(
            &self.forge_api_server,
            &self.client_config,
        ))
        .await
        .wrap_err("renew_certificates: Failed to build Forge API server client")?;

        let request = tonic::Request::new(rpc::MachineCertificateRenewRequest {});
        let machine_certificate_result = client
            .renew_machine_certificate(request)
            .await
            .wrap_err("renew_certificates: Error while executing the renew_certificates gRPC call")?
            .into_inner();

        tracing::info!("Received new machine certificate. Attempting to write to disk.");
        registration::write_certs(
            machine_certificate_result.machine_certificate,
            override_client_cert,
        )
        .await
        .wrap_err("renew_certificates: Failed to write certs to disk")?;

        Ok(())
    }
}
