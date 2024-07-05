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
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig, RetryConfig};

pub mod cloud_init;
pub mod ipxe;
pub mod tls;

pub struct RpcContext;

impl RpcContext {
    async fn get_pxe_instructions(
        arch: rpc::MachineArchitecture,
        machine_interface_id: rocket::serde::uuid::Uuid,
        url: String,
        client_config: ForgeClientConfig,
    ) -> Result<String, String> {
        let api_config = ApiConfig {
            url: &url,
            retry_config: RetryConfig::default(),
            client_config,
        };
        let mut client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
            .await
            .map_err(|err| err.to_string())?;
        let interface_id = Some(::rpc::common::Uuid {
            value: machine_interface_id.to_string(),
        });
        let request = tonic::Request::new(rpc::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: interface_id.clone(),
        });
        client
            .get_pxe_instructions(request)
            .await
            .map(|response| response.into_inner().pxe_script)
            .map_err(|error| {
                format!(
                    "Error in updating build needed flag for instance for machine {:?}; Error: {}.",
                    interface_id, error
                )
            })
    }
}
