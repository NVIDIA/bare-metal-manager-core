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

use std::time::Duration;

use ::rpc::forge::{AttestQuoteRequest, MachineCertificate};
use ::rpc::forge_tls_client::{self, ForgeClientConfig, ForgeTlsClient};
use ::rpc::machine_discovery as rpc_discovery;
use ::rpc::{forge as rpc, MachineDiscoveryInfo};
use eyre::WrapErr;
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
}

/// Data that is retrieved from the Forge API server during registration
#[derive(Debug, Clone)]
pub struct RegistrationData {
    /// The machine ID under which this machine is known in Forge
    pub machine_id: String,
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

    // discover_machine_once is a single future attempt of
    // trying to send MachineDiscoveryInfo to the API, creating
    // a new connection + wrapped request for each iteration
    // of the retry.
    async fn discover_machine_once(
        &self,
        client: ForgeTlsClient,
        info: MachineDiscoveryInfo,
        attempt: u32,
    ) -> Result<rpc::MachineDiscoveryResult, RegistrationError> {
        tracing::info!("Attempting to discover_machine (attempt: {})", attempt);

        // Create a new connection off of the ForgeTlsClient.
        let mut connection = match client.build(self.api_url.to_string()).await {
            Ok(forge_client) => forge_client,
            Err(e) => {
                tracing::error!("could not create tls client: {:?}", e);
                return Err(RegistrationError::TransportError(e.to_string()));
            }
        };
        tracing::debug!("register_machine client connection {:?}", connection);

        // Create a new request with the provided MachineDiscoveryInfo.
        let request = tonic::Request::new(info);
        tracing::debug!("register_machine request {:?}", request);

        // And now attempt to send the discover_machine request.
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
        // Create the client once, but due to ownership + things getting
        // moved into the retry future, it will need to be cloned. Defer
        // connection establishment to happen within the retry future.
        let client = forge_tls_client::ForgeTlsClient::new(self.config.clone());

        // The retry config is currently hard-coded in here to be
        // every minute for a week. Basically, keep trying every
        // minute for a while. This could probably become something
        // that is configurable.
        let config = RetryFutureConfig::new(self.retry.max)
            .fixed_backoff(Duration::from_secs(self.retry.secs));
        let mut attempt = 0;
        tryhard::retry_fn(|| {
            attempt += 1;
            self.discover_machine_once(client.clone(), info.clone(), attempt)
        })
        .with_config(config)
        .await
    }

    async fn attest_quote(
        &self,
        quote: &AttestQuoteRequest,
    ) -> Result<rpc::AttestQuoteResponse, RegistrationError> {
        let client = forge_tls_client::ForgeTlsClient::new(self.config.clone());

        // Create a new connection off of the ForgeTlsClient.
        let mut connection = client
            .build(self.api_url.to_string())
            .await
            .map_err(|err| RegistrationError::TransportError(err.to_string()))?;
        tracing::debug!("attest_quote client connection {:?}", connection);

        // Create a new request with the provided MachineDiscoveryInfo.
        let request = tonic::Request::new(quote.clone());
        tracing::debug!("attest_quote request {:?}", request);

        // And now attempt to send the discover_machine request.
        Ok(connection
            .attest_quote(request)
            .await
            .inspect_err(|err| {
                tracing::error!("Error attempting to attest_quote: {}", err.to_string())
            })?
            .into_inner())
    }
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
) -> Result<(RegistrationData, Option<rpc::AttestKeyBindChallenge>), RegistrationError> {
    let info = rpc::MachineDiscoveryInfo {
        machine_interface_id: machine_interface_id.map(|mid| mid.into()),
        discovery_data: Some(::rpc::forge::machine_discovery_info::DiscoveryData::Info(
            hardware_info,
        )),
        create_machine,
    };
    tracing::info!("register_machine discovery_info {:?}", info);

    let forge_client_config = match use_mgmt_vrf {
        true => ForgeClientConfig::new(root_ca, None)
            .use_mgmt_vrf()
            .map_err(|e| RegistrationError::TransportError(e.to_string()))?,
        false => ForgeClientConfig::new(root_ca, None),
    };
    tracing::debug!("register_machine client_config {:?}", forge_client_config);

    let response = RegistrationClient::new(forge_api, &forge_client_config, retry)
        .discover_machine(info)
        .await?;
    match write_certs(response.machine_certificate).await {
        Ok(()) => {}
        Err(_) if !require_client_certificates => {}
        Err(e) => return Err(RegistrationError::ClientCertificateError(e)),
    }

    let machine_id: String = response
        .machine_id
        .ok_or(RegistrationError::MissingMachineId)?
        .id;
    tracing::info!(machine_id, "Registered");

    Ok((
        RegistrationData { machine_id },
        response.attest_key_challenge,
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

    let forge_client_config = match use_mgmt_vrf {
        true => ForgeClientConfig::new(root_ca, None)
            .use_mgmt_vrf()
            .map_err(|e| RegistrationError::TransportError(e.to_string()))?,
        false => ForgeClientConfig::new(root_ca, None),
    };
    tracing::debug!("attest_quote client_config {:?}", forge_client_config);

    let response = RegistrationClient::new(forge_api, &forge_client_config, retry)
        .attest_quote(quote)
        .await?;

    let _ = write_certs(response.machine_certificate).await;

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
) -> Result<(), eyre::Report> {
    if let Some(mut machine_certificate) = machine_certificate {
        let mut combined_cert = Vec::with_capacity(
            machine_certificate.public_key.len() + machine_certificate.issuing_ca.len() + 1,
        );
        combined_cert.append(&mut machine_certificate.public_key);
        combined_cert.append(&mut "\n".to_string().into_bytes());
        combined_cert.append(&mut machine_certificate.issuing_ca);
        combined_cert.append(&mut "\n".to_string().into_bytes());
        tokio::fs::write(tls_default::CLIENT_CERT, combined_cert)
            .await
            .wrap_err(format!(
                "Failed to write new machine certificate PEM to {}",
                tls_default::CLIENT_CERT
            ))?;
        tracing::info!(
            "Wrote new machine certificate PEM to: {:?}",
            tls_default::CLIENT_CERT
        );

        tokio::fs::write(
            tls_default::CLIENT_KEY,
            machine_certificate.private_key.as_slice(),
        )
        .await
        .wrap_err(format!(
            "Failed to write new machine certificate key to: {}",
            tls_default::CLIENT_KEY
        ))?;
    } else {
        return Err(eyre::eyre!("write_certs: machine_certificate is empty"));
    }

    Ok(())
}
