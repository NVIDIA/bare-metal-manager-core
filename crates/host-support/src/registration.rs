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

use std::time::Duration;

use ::rpc::forge::{AttestQuoteRequest, MachineCertificate};
use ::rpc::forge_tls_client::{ForgeClientConfig, ForgeClientT, ForgeTlsClient};
use ::rpc::{MachineDiscoveryInfo, forge as rpc, machine_discovery as rpc_discovery};
use carbide_uuid::machine::MachineId;
use eyre::WrapErr;
use forge_tls::client_config::ClientCert;
use forge_tls::default as tls_default;
use tryhard::RetryFutureConfig;

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("Transport error {0}")]
    TransportError(String),
    #[error("Tonic status error {0}")]
    TonicStatusError(#[from] tonic::Status),
    #[error("Missing machine id in API server response. Should be impossible")]
    MissingMachineId,
    #[error("Attestation failed")]
    AttestationFailed,
    #[error("Failed to retrieve or write client certificate: {0}")]
    ClientCertificateError(eyre::Report),
    #[error("Missing certificate in DiscoverMachine reply")]
    MissingCertificate,
}

/// Data that is retrieved from the Forge API server during registration
#[derive(Debug, Clone)]
pub struct RegistrationData {
    /// The machine ID under which this machine is known in Forge
    pub machine_id: MachineId,
}

#[derive(Clone)]
pub struct DiscoveryRetry {
    pub secs: u64,
    pub max: u32,
}
// RegistrationClient is a small wrapper client that handles
// doing async retries of machine discovery requests. Since
// everything here is async, retrying futures gets interesting,
// because values get moved into them (as in needing to clone or
// recreate the underlying forge_tls_client, gRPC message, etc.
//
// This could have also just gone inline with register_machine,
// but breaking the code out like this does help to make
// the register_machine flow a little bit cleaner. This also
// could have just been its own function, instead of a struct,
// but I sort of have high hopes for maybe eventually making
// this so generic that we can use it for other things.
struct RegistrationClient<'a, 'c> {
    // api is the Forge API URL.
    api_url: &'a str,

    // config is, quite obviously, a reference
    // to a ForgeClientConfig to use.
    config: &'c ForgeClientConfig,

    retry: DiscoveryRetry,
}

impl<'a, 'c> RegistrationClient<'a, 'c> {
    // new creates a new RegistrationClient, where the
    // only things needed here are references to the API
    // URL and the corresponding ForgeClientConfig.
    fn new(api_url: &'a str, config: &'c ForgeClientConfig, retry: DiscoveryRetry) -> Self {
        Self {
            api_url,
            config,
            retry,
        }
    }

    // connect will create a new ForgeTlsClient and return an underlying
    // ForgeClientT connection for callers to leverage, returning an error
    // if we were unable to create a client (e.g. if there was an issue
    // loading certificates), or establish a connection. All calls from
    // devices -> carbide-api generally follow this pattern, so you merely
    // need to just do something like:
    //
    // let request = tonic::Request::new(your_request);
    // let mut connection = self.connect("<what-youre-doing>").await?;
    // let response = connection.your_api_endpoint(request).await?;
    //
    async fn connect(&self, purpose: &str) -> Result<ForgeClientT, RegistrationError> {
        tracing::debug!("creating tls client connection for {purpose}");
        let client = ForgeTlsClient::new(self.config);
        match client.build(self.api_url.to_string()).await {
            Ok(connection) => {
                tracing::debug!(
                    "created tls client connection for {purpose}: {:?}",
                    connection
                );
                Ok(connection)
            }
            Err(e) => {
                tracing::error!("could not create tls client for {purpose}: {:?}", e);
                Err(RegistrationError::TransportError(e.to_string()))
            }
        }
    }

    // discover_machine_once is a single future attempt of
    // trying to send MachineDiscoveryInfo to the API, creating
    // a new connection + wrapped request for each iteration
    // of the retry.
    async fn discover_machine_once(
        &self,
        info: MachineDiscoveryInfo,
        attempt: u32,
    ) -> Result<rpc::MachineDiscoveryResult, RegistrationError> {
        tracing::info!("Attempting to discover_machine (attempt: {})", attempt);

        // Create a new connection off of the ForgeTlsClient.
        let mut connection = self.connect("discover_machine_once").await?;

        // Create a new request with the provided MachineDiscoveryInfo.
        let request = tonic::Request::new(info);
        tracing::debug!("register_machine request {:?}", request);

        // And now attempt to send the request.
        Ok(connection
            .discover_machine(request)
            .await
            .inspect_err(|err| {
                tracing::error!(
                    "Error attempting to discover_machine (attempt: {}): {}",
                    attempt,
                    err.to_string()
                );
            })?
            .into_inner())
    }

    // discover_machine is a retrying wrapper around making
    // discover_machine gRPC calls to the Carbide API.
    pub async fn discover_machine(
        &mut self,
        info: MachineDiscoveryInfo,
    ) -> Result<rpc::MachineDiscoveryResult, RegistrationError> {
        // The retry config is currently hard-coded in here to be
        // every minute for a week. Basically, keep trying every
        // minute for a while. This could probably become something
        // that is configurable.
        let config = RetryFutureConfig::new(self.retry.max)
            .fixed_backoff(Duration::from_secs(self.retry.secs));
        let mut attempt = 0;
        tryhard::retry_fn(|| {
            attempt += 1;
            self.discover_machine_once(info.clone(), attempt)
        })
        .with_config(config)
        .await
    }

    async fn attest_quote(
        &self,
        quote: &AttestQuoteRequest,
    ) -> Result<rpc::AttestQuoteResponse, RegistrationError> {
        // Create a new connection off of the ForgeTlsClient.
        let mut connection = self.connect("attest_quote").await?;

        // Create a new request with the provided AttestQuoteRequest.
        let request = tonic::Request::new(quote.clone());
        tracing::debug!("attest_quote request {:?}", request);

        // And now attempt to send the request.
        Ok(connection
            .attest_quote(request)
            .await
            .inspect_err(|err| {
                tracing::error!("Error attempting to attest_quote: {}", err.to_string())
            })?
            .into_inner())
    }
}

// create_client_config creates a new ForgeClientConfig. All
// calls in here follow the same pattern, so this was moved out
// into its own function to clean up tons of duplication.
fn create_client_config(
    purpose: &str,
    use_mgmt_vrf: bool,
    root_ca: String,
) -> Result<ForgeClientConfig, RegistrationError> {
    let forge_client_config = match use_mgmt_vrf {
        true => ForgeClientConfig::new(root_ca, None)
            .use_mgmt_vrf()
            .map_err(|e| RegistrationError::TransportError(e.to_string()))?,
        false => ForgeClientConfig::new(root_ca, None),
    };
    tracing::debug!("{purpose} client_config {:?}", forge_client_config);
    Ok(forge_client_config)
}

/// Registers a machine at the Forge API server for further interactions
///
/// Returns information about the machine that is known by the API server
#[allow(clippy::too_many_arguments)]
pub async fn register_machine(
    forge_api: &str,
    root_ca: String,
    machine_interface_id: Option<uuid::Uuid>,
    hardware_info: rpc_discovery::DiscoveryInfo,
    use_mgmt_vrf: bool,
    retry: DiscoveryRetry,
    create_machine: bool,
    require_client_certificates: bool,
) -> Result<
    (
        RegistrationData,
        Option<rpc::AttestKeyBindChallenge>,
        Option<uuid::Uuid>,
    ),
    RegistrationError,
> {
    let info = rpc::MachineDiscoveryInfo {
        machine_interface_id: machine_interface_id.map(|mid| mid.into()),
        discovery_data: Some(::rpc::forge::machine_discovery_info::DiscoveryData::Info(
            hardware_info,
        )),
        create_machine,
    };
    tracing::info!("register_machine discovery_info {:?}", info);

    let forge_client_config = create_client_config("register_machine", use_mgmt_vrf, root_ca)?;
    let response = RegistrationClient::new(forge_api, &forge_client_config, retry)
        .discover_machine(info)
        .await?;

    if response.machine_certificate.is_none() && require_client_certificates {
        return Err(RegistrationError::MissingCertificate);
    }

    if response.machine_certificate.is_some() {
        match write_certs(response.machine_certificate, None).await {
            Ok(()) => {}
            Err(e) => return Err(RegistrationError::ClientCertificateError(e)),
        }
    }

    let machine_id = response
        .machine_id
        .ok_or(RegistrationError::MissingMachineId)?;
    tracing::info!(%machine_id, "Registered");

    Ok((
        RegistrationData { machine_id },
        response.attest_key_challenge,
        response.machine_interface_id.map(uuid::Uuid::from),
    ))
}

pub async fn attest_quote(
    forge_api: &str,
    root_ca: String,
    use_mgmt_vrf: bool,
    retry: DiscoveryRetry,
    quote: &AttestQuoteRequest,
) -> Result<bool, RegistrationError> {
    tracing::info!("registration client sending attest_quote");

    let forge_client_config = create_client_config("attest_quote", use_mgmt_vrf, root_ca)?;
    let response = RegistrationClient::new(forge_api, &forge_client_config, retry)
        .attest_quote(quote)
        .await?;

    let _ = write_certs(response.machine_certificate, None).await;

    tracing::info!(
        "Attestation result is {}",
        if response.success {
            "SUCCESS"
        } else {
            "FAILURE"
        }
    );

    Ok(response.success)
}

pub async fn write_certs(
    machine_certificate: Option<MachineCertificate>,
    override_client_cert: Option<&ClientCert>,
) -> Result<(), eyre::Report> {
    if let Some(mut machine_certificate) = machine_certificate {
        let mut combined_cert = Vec::with_capacity(
            machine_certificate.public_key.len() + machine_certificate.issuing_ca.len() + 1,
        );
        combined_cert.append(&mut machine_certificate.public_key);
        combined_cert.append(&mut "\n".to_string().into_bytes());
        combined_cert.append(&mut machine_certificate.issuing_ca);
        combined_cert.append(&mut "\n".to_string().into_bytes());
        let (client_cert, client_key) = match override_client_cert {
            Some(c) => (c.cert_path.as_str(), c.key_path.as_str()),
            None => (tls_default::CLIENT_CERT, tls_default::CLIENT_KEY),
        };
        tokio::fs::write(client_cert, combined_cert)
            .await
            .wrap_err(format!(
                "Failed to write new machine certificate PEM to {client_cert}"
            ))?;
        tracing::info!("Wrote new machine certificate PEM to: {:?}", client_cert);

        tokio::fs::write(client_key, machine_certificate.private_key.as_slice())
            .await
            .wrap_err(format!(
                "Failed to write new machine certificate key to: {client_key}"
            ))?;
    } else {
        return Err(eyre::eyre!("write_certs: machine_certificate is empty"));
    }

    Ok(())
}
