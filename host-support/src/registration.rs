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

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use ::rpc::machine_discovery as rpc_discovery;

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("Transport error {0}")]
    TransportError(String),
    #[error("Tonic status error {0}")]
    TonicStatusError(#[from] tonic::Status),
    #[error("Missing or invalid machine id in API server response for machine interface ID {0}")]
    InvalidMachineId(uuid::Uuid),
}

/// Data that is retrieved from the Forge API server during registration
#[derive(Debug, Clone)]
pub struct RegistrationData {
    /// The machine ID under which this machine is known in Forge
    pub machine_id: String,
}

/// Registers a machine at the Forge API server for further interactions
///
/// Returns information about the machine that is known by the API server
pub async fn register_machine(
    forge_api: &str,
    root_ca: String,
    machine_interface_id: uuid::Uuid,
    hardware_info: rpc_discovery::DiscoveryInfo,
) -> Result<RegistrationData, RegistrationError> {
    let info = rpc::MachineDiscoveryInfo {
        machine_interface_id: Some(machine_interface_id.into()),
        discovery_data: Some(::rpc::forge::machine_discovery_info::DiscoveryData::Info(
            hardware_info,
        )),
    };
    let mut client = forge_tls_client::ForgeTlsClient::new(root_ca)
        .connect(forge_api.to_string())
        .await
        .map_err(|err| RegistrationError::TransportError(err.to_string()))?;
    let request = tonic::Request::new(info);

    let response = client
        .discover_machine(request)
        .await
        .map_err(|err| {
            tracing::error!(
                "Error while executing the discover_machine gRPC call: {}",
                err.to_string()
            );
            err
        })?
        .into_inner();

    if let Some(machine_certificate) = response.machine_certificate {
        let _ = tokio::fs::write(
            "/tmp/machine_cert.pem",
            machine_certificate.public_key.as_slice(),
        )
        .await;
        let _ = tokio::fs::write(
            "/tmp/machine_cert.key",
            machine_certificate.private_key.as_slice(),
        )
        .await;
        let _ = tokio::fs::write(
            "/tmp/issuing_cert.pem",
            machine_certificate.issuing_ca.as_slice(),
        )
        .await;
    }

    let machine_id: String = response
        .machine_id
        .ok_or(RegistrationError::InvalidMachineId(machine_interface_id))?
        .id;

    tracing::info!("Registered machine with ID {machine_id} for interface {machine_interface_id} at Forge API server");

    Ok(RegistrationData { machine_id })
}
