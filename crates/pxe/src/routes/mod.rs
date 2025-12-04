/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use carbide_uuid::machine::MachineInterfaceId;

pub(crate) mod cloud_init;
pub(crate) mod ipxe;
pub(crate) mod metrics;
pub(crate) mod tls;

pub struct RpcContext;

impl RpcContext {
    async fn get_pxe_instructions(
        arch: rpc::MachineArchitecture,
        interface_id: MachineInterfaceId,
        product: Option<String>,
        url: &str,
        client_config: &ForgeClientConfig,
    ) -> Result<String, String> {
        let api_config = ApiConfig::new(url, client_config);
        let mut client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
            .await
            .map_err(|err| err.to_string())?;
        let request = tonic::Request::new(rpc::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(interface_id),
            product,
        });
        client
            .get_pxe_instructions(request)
            .await
            .map(|response| response.into_inner().pxe_script)
            .map_err(|error| {
                format!(
                    "Error in updating build needed flag for instance for machine {interface_id:?}; Error: {error}."
                )
            })
    }
}
